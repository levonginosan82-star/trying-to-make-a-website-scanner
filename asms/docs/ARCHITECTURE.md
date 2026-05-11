# ASMS — Architecture

> Status: design document. Sections marked **[scaffolded]** describe components
> that are specified here and have stub interfaces in code, but are not fully
> implemented in this PR. Sections marked **[implemented]** are runnable today.

## 1. Goals

ASMS is a multi-tenant enterprise security platform that automates the
discovery, assessment, prioritisation, and tracking of vulnerabilities across
an organisation's external and internal attack surface, application code, and
infrastructure. It is designed to replace ad-hoc usage of point tools
(Acunetix, Netsparker, Detectify, ImmuniWeb, Qualys, Fortify, Hacker Target)
with a single platform offering:

- DAST (dynamic application security testing) with SPA support.
- EASM (external attack surface management).
- API and mobile-backend testing.
- Continuous host/infrastructure vulnerability management.
- SAST and IaC scanning integrated into CI/CD.
- Risk-based prioritisation (CVSS v3 + exploit intelligence).
- Compliance reporting (PCI DSS, ISO 27001, GDPR, HIPAA, CIS).

## 2. Logical architecture

```
                            ┌─────────────────────────┐
                            │   React Control Panel   │
                            └────────────┬────────────┘
                                         │  HTTPS / OAuth2 (PKCE) + MFA
                            ┌────────────▼────────────┐
                            │      API Gateway        │  FastAPI
                            │  AuthN / AuthZ / RBAC   │  + envoy (rate limit)
                            └─┬───────┬───────┬───────┘
                              │       │       │
            ┌─────────────────┘       │       └───────────────────┐
            │                         │                           │
   ┌────────▼────────┐      ┌─────────▼─────────┐     ┌──────────▼──────────┐
   │ Scan Orchestrator│     │  Findings Service │     │  Reporting / Export │
   │ - scan lifecycle │     │ - dedup, triage   │     │ - PDF / JSON / XML  │
   │ - scheduling     │     │ - status, comments│     │ - exec summary      │
   └────────┬─────────┘     └─────────┬─────────┘     └──────────┬──────────┘
            │                         │                          │
            │              ┌──────────▼──────────┐               │
            │              │   PostgreSQL (OLTP) │◄──────────────┘
            │              │   users, scans,     │
            │              │   findings, assets  │
            │              └──────────┬──────────┘
            │                         │
            │              ┌──────────▼──────────┐
            │              │ Elasticsearch (raw) │ scan evidence, logs
            │              └─────────────────────┘
            │
   ┌────────▼────────────────────────────────────────────────────────────┐
   │                    Message broker  (RabbitMQ / Kafka)                │
   │   Queues: dast.crawler, dast.headers, easm.subdomains, easm.nmap,    │
   │           sast.semgrep, iac.checkov, api.fuzz, ml.classify, …        │
   └────────┬─────────┬─────────┬─────────┬─────────┬─────────────────────┘
            │         │         │         │         │
       ┌────▼───┐ ┌───▼────┐ ┌──▼────┐ ┌──▼────┐ ┌──▼────┐  Celery workers,
       │ DAST   │ │ EASM   │ │ API   │ │ SAST  │ │ ML    │  containerised,
       │ worker │ │ worker │ │ worker│ │ worker│ │ worker│  horizontally
       └────────┘ └────────┘ └───────┘ └───────┘ └───────┘  scaled in k8s
```

## 3. Services

### 3.1 API Gateway  **[scaffolded]**
- FastAPI behind nginx/envoy.
- OAuth2 (authorization-code + PKCE) with MFA (TOTP, WebAuthn).
- RBAC: `Org Admin`, `Security Lead`, `Engineer`, `Auditor`, `API Client`.
- Per-tenant rate limits.

### 3.2 Scan Orchestrator  **[scaffolded]**
- Manages the scan lifecycle (`queued → running → completed/failed`).
- Splits a scan request into per-check tasks and routes each to the correct
  queue based on scanner type.
- Tracks worker heartbeats; reschedules tasks abandoned by dead workers.
- Enforces per-tenant concurrency quotas.

### 3.3 Scanner workers  **[partially implemented]**
Each worker is a containerised process that subscribes to one or more queues
and implements one or more `Check` plugins. The base `Check` interface is in
`worker/asms_worker/checks/base.py`:

```python
class Check(Protocol):
    name: str
    category: str        # dast | easm | api | sast | iac | mobile | …
    severity_default: Severity
    def run(self, ctx: CheckContext) -> Iterable[Finding]: ...
```

Worker families (all consume the same job envelope; see §5):

| Family | Status | Notes |
| --- | --- | --- |
| `dast.headers` | **implemented** | This PR — security-header analysis |
| `dast.crawler` | [scaffolded] | Playwright-based SPA crawl, CSRF token learner, CAPTCHA bypass (auth cookies / API token plug-in) |
| `dast.injection` | [scaffolded] | SQLi, XSS, SSRF, RCE, LFI/RFI via payload templates + reflected-response and out-of-band oracles |
| `dast.business_logic` | [scaffolded] | Replay-and-mutate auth flows; rate-limit/IDOR detection |
| `easm.subdomains` | [scaffolded] | wordlist + cert-transparency + passive DNS |
| `easm.dns` | [scaffolded] | SPF/DKIM/DMARC, NS, MX, CAA |
| `easm.ports` | [scaffolded] | masscan + nmap service detection |
| `easm.cert` | [scaffolded] | crt.sh + Censys monitoring for leaked SSL |
| `api.scanner` | [scaffolded] | OpenAPI/Swagger, GraphQL introspection, gRPC reflection fuzzers |
| `mobile.masvs` | [scaffolded] | OWASP MASVS checks against mobile backends |
| `infra.host` | [scaffolded] | Authenticated host scan, package CVE matching |
| `compliance` | [scaffolded] | PCI/ISO/GDPR/HIPAA/CIS rule packs derived from findings |
| `sast.scanner` | [scaffolded] | Semgrep + trufflehog (secrets) on a repo URL |
| `iac.scanner` | [scaffolded] | Checkov / kube-bench / tfsec on Docker/K8s/Terraform |
| `darkweb.monitor` | [scaffolded] | HIBP-style + private feed integrations |
| `ml.classify` | [scaffolded] | gradient-boosted classifier that downgrades likely false positives based on response, payload, and historical labels |

### 3.4 Findings service  **[scaffolded]**
- Receives `Finding` events from workers, normalises, deduplicates against
  the `findings` table (fingerprint = asset_id + check_id + parameter + payload),
  and writes/updates `vulnerabilities` rows.
- Computes risk score = `CVSS_base × exploit_factor × asset_criticality`.
- Emits webhooks (Slack, Jira, ServiceNow, MS Teams).

### 3.5 Reporting service  **[scaffolded]**
- PDF (executive summary + technical detail), JSON, XML (SARIF), CSV.
- Custom report designer driven by Jinja templates per organisation.

## 4. Data stores

- **PostgreSQL** — relational source of truth: tenants, users, assets, scans,
  vulnerabilities, findings, comments, audit log, settings. Schema:
  `asms/db/schema.sql`.
- **Elasticsearch** — raw scanner evidence (request/response bodies, screenshots,
  crawler graphs, packet captures) and operational logs. Indexed by
  `scan_id` and `finding_id` for fast drill-down.
- **Object storage (S3-compatible)** — large artefacts (PCAPs, screenshots,
  generated PDF reports), referenced from Postgres by URL.
- **Redis** — short-lived: locks, rate limits, ephemeral worker state.

## 5. Job envelope

Every queue message is a JSON envelope:

```json
{
  "task_id":   "uuid",
  "scan_id":   "uuid",
  "tenant_id": "uuid",
  "asset_id":  "uuid",
  "check":     "dast.headers",
  "target":    { "url": "https://example.com", "method": "GET" },
  "options":   { "follow_redirects": true, "timeout_s": 15 },
  "auth":      { "type": "bearer", "ref": "vault:secret/tenant/x/y" },
  "created_at":"2025-01-01T00:00:00Z"
}
```

Workers ack only after persisting findings; on failure they nack with a
retry counter capped by orchestrator policy.

## 6. Security model

- All inter-service traffic is mTLS inside the cluster.
- Secrets (target credentials, integration tokens) live in HashiCorp Vault;
  workers receive a short-lived reference, never the secret value, except at
  the moment of use.
- Tenants are isolated at the database level via row-level security
  (`tenant_id` predicate) and at the queue level via per-tenant routing keys.
- Audit log captures every state change to `vulnerabilities` and every
  authentication event; immutable, append-only.
- Scanners run as unprivileged users in network-restricted egress namespaces;
  destructive payloads are disabled by default. The "PoC mode" only collects
  evidence sufficient to prove exploitability (no data exfiltration, no
  persistence).

## 7. Deployment

- Workers are stateless containers; horizontally scaled by `HorizontalPodAutoscaler`
  on queue depth.
- Helm charts deploy: gateway, orchestrator, findings service, reporting,
  worker pools (per family), Postgres (operator), Elasticsearch (ECK), RabbitMQ
  (operator), Redis, Vault.
- CI/CD: GitHub Actions / GitLab CI build per-service images, sign with cosign,
  push to registry; ArgoCD syncs to staging then production.

## 8. CI/CD integration  **[scaffolded]**

Per-pipeline plugin (`asms-cli`) invokes a SAST scan and/or a DAST scan against
a preview deployment, posts a SARIF artefact, and fails the build on findings
exceeding a configured severity threshold. Reference implementations:

- GitHub Action (`uses: asms/action-scan@v1`)
- GitLab CI template (`include: project: asms/templates file: scan.yml`)
- Jenkins shared library (`asmsScan severity: 'high'`)

## 9. Open extension points

- Custom checks: drop a class implementing `Check` into a tenant's plugin
  package; the orchestrator loads it into an isolated worker pool.
- Custom report templates: Jinja templates with sandboxed filters.
- Webhooks and SIEM forwarders for findings (CEF, LEEF, JSON).

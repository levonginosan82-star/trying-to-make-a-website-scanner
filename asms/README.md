# ASMS — Automated Security Management System

ASMS is an enterprise vulnerability-management platform: a successor in spirit to
Acunetix, Netsparker, Detectify, ImmuniWeb, Qualys, Fortify, and Hacker Target.

This directory hosts the architecture, database schema, a runnable Python scanner
worker, and a Tailwind-based control-panel UI. It lives alongside the original
single-host `website-scanner/` and is intended to evolve into the production
platform; the legacy scanner can be wrapped as a worker module during migration.

## Layout

| Path | Purpose |
| --- | --- |
| `docs/ARCHITECTURE.md` | System architecture, microservices, queues, scanners, security model |
| `db/schema.sql` | PostgreSQL schema (organizations, users, assets, scans, vulnerabilities, findings, …) |
| `worker/` | Python scanner worker. Pluggable check registry; ships a DAST security-headers check. |
| `dashboard/index.html` | Static control panel (Tailwind CDN) with Security Score, severity breakdown, latest critical threats, filterable findings table |
| `api/` | (Scaffolded) FastAPI gateway stub for the control plane |

## Quick start

### 1. Worker (Python 3.11+)

```bash
cd asms/worker
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]

# Run the demo scan against a public target. Prints findings as JSON.
python -m asms_worker.cli scan --url https://example.com

# Run unit tests
pytest
```

You can also run it as a Celery worker (RabbitMQ/Redis broker — see
`docs/ARCHITECTURE.md`):

```bash
celery -A asms_worker.celery_app worker --loglevel=INFO -Q dast.headers
```

### 2. Database

```bash
psql -U postgres -f asms/db/schema.sql
```

### 3. Dashboard

Open `asms/dashboard/index.html` directly in a browser, or serve it:

```bash
python -m http.server --directory asms/dashboard 8080
# -> http://localhost:8080
```

The dashboard ships with mock data in `dashboard/data/sample.json` so it renders
without a backend; swap the fetch URL in `index.html` to point at the FastAPI
gateway once it is deployed.

## Scope of this PR

Production-ready in this PR:
- Architecture documentation and threat model.
- PostgreSQL schema with all required fields (`id`, `type`, `severity`, `cvss`,
  `description`, `url/parameter`, `status`).
- Python worker that consumes a task, performs an HTTP request, and parses
  security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy, cookie flags) into findings, with unit
  tests.
- Tailwind dashboard with Security Score, severity breakdown, and latest
  critical threats.

Scaffolded / specified-but-not-implemented in this PR (see
`docs/ARCHITECTURE.md` for design):
- Full DAST crawler (SPA-aware), CSRF/CAPTCHA bypass.
- EASM (subdomain bruteforce, WHOIS, DNS, Nmap, cert transparency monitoring).
- ML-based false-positive reduction and dark-web leak monitoring.
- API scanning (OAS/GraphQL/gRPC).
- SAST and IaC scanners; CI/CD plugins.
- FastAPI control plane and React SPA.

Each scanner module follows the same `Check` interface (see
`worker/asms_worker/checks/base.py`) so new families can be added without
touching the orchestrator.

## Legal

Use only against systems you are authorised to test.

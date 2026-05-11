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
| `worker/` | Python scanner worker. Pluggable check registry: `dast.headers`, `dast.tls`, `dast.sensitive_paths`, `dast.tech_disclosure`, `easm.dns`, `sast.secrets`. |
| `dashboard/index.html` | Static control panel (Tailwind CDN) with Security Score, severity breakdown, latest critical threats, filterable findings table |
| `api/` | FastAPI control plane: `/scans`, `/vulnerabilities`, `/security-score`. SQLAlchemy + Pydantic v2, async SQLite by default. |

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
without a backend. To point it at a running API, open the dashboard with a
`?api=` query string:

```
http://localhost:8080/?api=http://localhost:8000&org=acme
```

It will fetch live data from the API and fall back to the mock JSON if the API
is unreachable.

### 4. API (FastAPI control plane)

```bash
cd asms/api
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]

# Seed the SQLite dev DB with the same data the dashboard ships with
python -m asms_api.seed

uvicorn asms_api.main:app --reload --port 8000
# -> http://localhost:8000/docs
```

## Scope of this PR

Production-ready:
- Architecture documentation and threat model.
- PostgreSQL schema with all required fields (`id`, `type`, `severity`, `cvss`,
  `description`, `url/parameter`, `status`).
- FastAPI control plane (`/scans`, `/vulnerabilities`, `/security-score`) with
  SQLAlchemy ORM, Pydantic v2, async SQLite for local dev / Postgres for prod.
- Python worker with six pluggable checks, all under unit-test coverage:
  - `dast.headers` — security-header analyser.
  - `dast.tls` — certificate expiry, hostname mismatch, deprecated protocols.
  - `dast.sensitive_paths` — high-signal probes (`.git/HEAD`, `.env`, etc.).
  - `dast.tech_disclosure` — version fingerprinting on response headers.
  - `easm.dns` — SPF/DKIM/DMARC/CAA posture.
  - `sast.secrets` — regex-based secret detection for source trees and CI.
- Tailwind dashboard with Security Score, severity breakdown, latest critical
  threats, and live API wiring via `?api=` query param.
- GitHub Actions CI: ruff + pytest on every push and PR.

Scaffolded / specified-but-not-implemented (see `docs/ARCHITECTURE.md`):
- Full DAST crawler (SPA-aware), CSRF/CAPTCHA bypass.
- ML-based false-positive reduction and dark-web leak monitoring.
- API scanning (OAS/GraphQL/gRPC).
- IaC scanner; broader CI/CD plug-ins.
- React SPA frontend.

Each scanner module follows the same `Check` interface (see
`worker/asms_worker/checks/base.py`) so new families can be added without
touching the orchestrator.

## Legal

Use only against systems you are authorised to test.

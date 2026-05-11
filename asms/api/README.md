# ASMS API (control plane)

FastAPI service that exposes the ASMS catalogue: assets, scans, vulnerabilities,
and the per-org security score. SQLAlchemy 2.0 ORM models mirror the SQL
schema in `asms/db/schema.sql`. The default deployment runs on SQLite for
easy local dev; point `ASMS_DATABASE_URL` at a Postgres DSN for production.

## Run locally

```bash
cd asms/api
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]

# Seeds the SQLite DB with a demo tenant + a dozen sample findings.
python -m asms_api.seed

uvicorn asms_api.main:app --reload --port 8000
# -> http://localhost:8000/docs
```

Endpoints:

- `GET  /health` — liveness probe.
- `GET  /api/v1/organizations/{org}/security-score` — score + severity counts.
- `GET  /api/v1/organizations/{org}/vulnerabilities` — filterable list.
- `POST /api/v1/scans` — enqueue a scan (returns immediately with `queued` status).
- `GET  /api/v1/scans/{scan_id}` — scan detail and current status.

CORS is wide-open by default so the static dashboard at
`asms/dashboard/index.html` can talk to it directly.

## Tests

```bash
pytest
```

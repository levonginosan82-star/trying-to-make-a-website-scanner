---
name: testing-asms
description: End-to-end test the ASMS dashboard and scanner worker. Use when verifying changes to asms/dashboard/, asms/worker/, or the asms_worker package — covers how to serve the static UI, where the mock data lives, what assertions distinguish a working build, and how to smoke-test the worker CLI.
---

# Testing the ASMS module

The ASMS module has two runtime-testable surfaces:

1. **Static dashboard** under `asms/dashboard/` — pure HTML + Tailwind CDN + vanilla JS that `fetch`es `data/sample.json` and renders. Must be served via HTTP because `file://` blocks `fetch`.
2. **Python worker** under `asms/worker/` — Celery-compatible package with a Click CLI (`python -m asms_worker.cli`).

The PostgreSQL schema (`asms/db/schema.sql`) is not runtime-testable without a Postgres instance; verify it by parsing through the real PG grammar via `pglast`:

```bash
pip install pglast
python -c "import pglast; pglast.parse_sql(open('asms/db/schema.sql').read()); print('ok')"
```

## Devin Secrets Needed

None — all testing is local against mock data and `https://example.com`.

## Setup (one-time)

```bash
cd asms/worker
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
```

Unit tests:

```bash
cd asms/worker && . .venv/bin/activate && pytest      # 15 tests, ~0.4s
ruff check .                                           # must be clean
```

## Dashboard testing

Serve and open:

```bash
python -m http.server --directory asms/dashboard 8080
# -> http://localhost:8080
```

Reliable browser maximisation (Linux/Ubuntu):

```bash
sudo apt-get install -y wmctrl 2>/dev/null
wmctrl -r :ACTIVE: -b add,maximized_vert,maximized_horz
```

Do NOT use `xdotool key super+Up` — it tiles to half-screen on many WMs.

### Where the visible numbers come from

All dashboard numbers come from `asms/dashboard/data/sample.json`. If you change
that file, the assertions below shift; re-derive them with:

```bash
python3 -c "
import json
d = json.load(open('asms/dashboard/data/sample.json'))
print('score:', d['security_score'])
print('breakdown:', d['severity_breakdown'])
print('total vulns:', len(d['vulnerabilities']))
for v in sorted([v for v in d['vulnerabilities'] if v['severity']=='critical'], key=lambda x: -x['cvss']):
    print(' ', v['cvss'], v['title'])
"
```

### Score-band thresholds (from `js/dashboard.js`)

```
score >= 85  -> Healthy (emerald)
score >= 65  -> Watch (amber)
score >= 40  -> At risk (orange)
else         -> Critical (red)
```

With the default mock data (score = 62) the band is **At risk**.

### Adversarial assertions that distinguish broken from working

- Big score value matches `security_score` from JSON, not `--`.
- KPI strip exactly matches `severity_breakdown` (critical/high/medium/low/info).
- "Latest critical threats" lists items where `severity === 'critical'` sorted by `cvss` descending, capped at 5. Broken sort/slice would reorder or include non-criticals.
- Vulnerability table filters use AND semantics across severity, status, and a text search that hits `title|asset|url|parameter|type`. To prove the AND logic: severity=Critical reduces to 4; adding search "ssrf" reduces to 1.
- Status=Fixed against the default data yields zero rows + the literal text "No findings match the current filters.".

### `computer` console gotcha

`computer(action="console")` sometimes reports "Chrome is not in the foreground" even when Chrome clearly is. The screen-recorded screenshots are usable evidence; fall back to visual inspection if console scripting fails repeatedly. Reproducing the page state in the shell is faster than fighting the focus check.

## Worker CLI smoke test

```bash
. asms/worker/.venv/bin/activate
python -m asms_worker.cli scan --url https://example.com
```

Against `https://example.com` the CLI returns ~7 findings (the site has no
security headers and exposes a server banner). Assertions:

- Exit code 0.
- Output is valid JSON (`json.load` succeeds).
- At least one entry has `"type": "missing-csp"` and `"severity": "medium"`.
- Every entry has a non-empty `fingerprint` and ISO-8601 `discovered_at`.

## Common pitfalls

- Opening `index.html` via `file://` — `fetch()` of `data/sample.json` is blocked. Always serve over HTTP.
- Forgetting to activate the venv before running the CLI — the entry point lives in `asms/worker/.venv/bin/`.
- Editing `sample.json` without re-deriving the expected counts/orderings.
- Assuming Celery works without a broker — the unit tests in `tests/test_tasks.py` call the task directly (`run_check.run(envelope)`) to avoid that.

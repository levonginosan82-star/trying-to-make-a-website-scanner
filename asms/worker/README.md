# ASMS scanner worker

Pluggable Python worker that consumes scan tasks from a queue and emits
`Finding` records. Ships with a DAST security-headers check; new checks
implement the `Check` protocol in `asms_worker.checks.base`.

## Run a one-off scan

```bash
pip install -e .[dev]
python -m asms_worker.cli scan --url https://example.com
```

## Run as a Celery worker

```bash
export ASMS_BROKER_URL=amqp://guest:guest@localhost:5672//
celery -A asms_worker.celery_app worker --loglevel=INFO -Q dast.headers
```

Submit a task from another process:

```python
from asms_worker.celery_app import app
app.send_task(
    "asms_worker.tasks.run_check",
    kwargs={
        "envelope": {
            "task_id": "...",
            "scan_id": "...",
            "tenant_id": "...",
            "asset_id": "...",
            "check": "dast.headers",
            "target": {"url": "https://example.com"},
        }
    },
    queue="dast.headers",
)
```

## Tests

```bash
pytest
```

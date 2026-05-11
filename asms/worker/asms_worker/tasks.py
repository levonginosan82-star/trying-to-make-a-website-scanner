"""Celery task that runs a single check from the queue envelope.

The envelope schema is documented in `asms/docs/ARCHITECTURE.md` §5.
"""

from __future__ import annotations

import logging
from typing import Any

from asms_worker.celery_app import app
from asms_worker.checks.base import CheckContext
from asms_worker.registry import REGISTRY

logger = logging.getLogger(__name__)


@app.task(
    name="asms_worker.tasks.run_check",
    bind=True,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_kwargs={"max_retries": 3},
)
def run_check(self, envelope: dict[str, Any]) -> list[dict[str, Any]]:
    """Execute a single check described by `envelope` and return findings.

    Args:
        envelope: queue message as defined in docs/ARCHITECTURE.md §5.

    Returns:
        A list of dictionaries; each entry is a Finding ready for the
        findings service to persist.
    """
    target = envelope["target"]
    check_name = envelope["check"]
    options = envelope.get("options", {}) or {}

    logger.info(
        "Running check %s for tenant %s scan %s url %s",
        check_name,
        envelope.get("tenant_id"),
        envelope.get("scan_id"),
        target.get("url"),
    )

    check = REGISTRY.get(check_name)
    ctx = CheckContext(
        url=target["url"],
        method=target.get("method", "GET"),
        tenant_id=envelope.get("tenant_id"),
        asset_id=envelope.get("asset_id"),
        scan_id=envelope.get("scan_id"),
        options=options,
    )
    findings = [f.to_dict() for f in check.run(ctx)]
    logger.info("Check %s produced %d finding(s)", check_name, len(findings))
    return findings

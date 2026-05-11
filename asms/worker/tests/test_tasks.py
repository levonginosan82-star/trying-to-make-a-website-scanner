"""Tests for the Celery task layer (without a broker)."""

from __future__ import annotations

import httpx
import respx

from asms_worker.tasks import run_check


def test_run_check_returns_findings_as_dicts() -> None:
    url = "https://example.com/"
    with respx.mock(assert_all_called=False) as r:
        r.get(url).mock(return_value=httpx.Response(200, headers={}))
        envelope = {
            "task_id": "t1",
            "scan_id": "s1",
            "tenant_id": "tenant",
            "asset_id": "asset",
            "check": "dast.headers",
            "target": {"url": url, "method": "GET"},
            "options": {"timeout_s": 5},
        }
        # Celery binds `self` to the task; call the underlying function.
        result = run_check.run(envelope)
    assert isinstance(result, list)
    assert all(isinstance(item, dict) for item in result)
    assert any(item["type"] == "missing-csp" for item in result)
    # Tenant/asset/scan ids are propagated.
    for item in result:
        assert item["tenant_id"] == "tenant"
        assert item["asset_id"] == "asset"
        assert item["scan_id"] == "s1"
        assert "fingerprint" in item

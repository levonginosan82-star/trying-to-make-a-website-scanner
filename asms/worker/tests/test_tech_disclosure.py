"""Tests for the tech-disclosure check."""

from __future__ import annotations

import httpx
import respx

from asms_worker.checks.base import CheckContext
from asms_worker.checks.tech_disclosure import TechDisclosureCheck


def test_php_version_disclosure():
    ctx = CheckContext(url="https://target.example/", method="GET")
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://target.example/").mock(
            return_value=httpx.Response(
                200, headers={"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3"}
            )
        )
        findings = list(TechDisclosureCheck().run(ctx))
    products = {f.evidence["matched_product"] for f in findings}
    assert "PHP" in products
    assert "nginx" in products
    # Each emits LOW severity, never critical.
    assert all(f.severity.value == "low" for f in findings)


def test_no_headers_emits_nothing():
    ctx = CheckContext(url="https://target.example/", method="GET")
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://target.example/").mock(
            return_value=httpx.Response(200, headers={})
        )
        findings = list(TechDisclosureCheck().run(ctx))
    assert findings == []


def test_iis_version_extracted():
    ctx = CheckContext(url="https://target.example/", method="GET")
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://target.example/").mock(
            return_value=httpx.Response(200, headers={"Server": "Microsoft-IIS/10.0"})
        )
        findings = list(TechDisclosureCheck().run(ctx))
    assert any(f.evidence["matched_version"] == "10.0" for f in findings)


def test_fetch_failure_yields_info_finding():
    ctx = CheckContext(url="https://target.example/", method="GET")
    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://target.example/").mock(side_effect=httpx.ConnectError("boom"))
        findings = list(TechDisclosureCheck().run(ctx))
    assert len(findings) == 1
    assert findings[0].type == "tech-fetch-failed"
    assert findings[0].severity.value == "info"

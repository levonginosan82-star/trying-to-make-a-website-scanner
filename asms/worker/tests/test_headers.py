"""Unit tests for the security-headers check (offline via respx)."""

from __future__ import annotations

import httpx
import pytest
import respx

from asms_worker.checks.base import CheckContext, Severity
from asms_worker.checks.headers import SecurityHeadersCheck


def _run(url: str, response: httpx.Response) -> list:
    with respx.mock(assert_all_called=False) as r:
        r.get(url).mock(return_value=response)
        client = httpx.Client()
        try:
            ctx = CheckContext(url=url, client=client)
            findings = list(SecurityHeadersCheck().run(ctx))
        finally:
            client.close()
        return findings


def _types(findings) -> set[str]:
    return {f.type for f in findings}


def test_no_headers_at_all_emits_every_missing_finding() -> None:
    response = httpx.Response(200, headers={}, request=httpx.Request("GET", "https://t.example"))
    findings = _run("https://t.example", response)
    types = _types(findings)
    # HTTPS-only header is included.
    assert "missing-hsts" in types
    assert "missing-csp" in types
    assert "missing-x-content-type-options" in types
    assert "missing-x-frame-options" in types
    assert "missing-referrer-policy" in types
    assert "missing-permissions-policy" in types


def test_http_target_skips_https_only_headers() -> None:
    response = httpx.Response(200, headers={}, request=httpx.Request("GET", "http://t.example"))
    findings = _run("http://t.example", response)
    types = _types(findings)
    assert "missing-hsts" not in types
    assert "missing-csp" in types


def test_fully_hardened_response_has_no_findings() -> None:
    headers = {
        "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
        "content-security-policy": "default-src 'self'; script-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()",
    }
    response = httpx.Response(
        200, headers=headers, request=httpx.Request("GET", "https://t.example")
    )
    assert _run("https://t.example", response) == []


def test_weak_hsts_max_age_flagged() -> None:
    headers = {
        "strict-transport-security": "max-age=60",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()",
    }
    response = httpx.Response(
        200, headers=headers, request=httpx.Request("GET", "https://t.example")
    )
    findings = _run("https://t.example", response)
    assert "weak-hsts" in _types(findings)


def test_csp_unsafe_inline_flagged() -> None:
    headers = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()",
    }
    response = httpx.Response(
        200, headers=headers, request=httpx.Request("GET", "https://t.example")
    )
    findings = _run("https://t.example", response)
    assert "weak-csp-unsafe" in _types(findings)


def test_insecure_cookie_flags_flagged() -> None:
    response = httpx.Response(
        200,
        headers={
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
            # Missing Secure, HttpOnly, SameSite
            "set-cookie": "sid=abc123",
        },
        request=httpx.Request("GET", "https://t.example"),
    )
    findings = _run("https://t.example", response)
    insecure = [f for f in findings if f.type == "insecure-cookie"]
    assert len(insecure) == 1
    problems = insecure[0].evidence["problems"]
    assert "missing-secure" in problems
    assert "missing-httponly" in problems
    assert "missing-samesite" in problems


def test_server_banner_disclosure_flagged() -> None:
    response = httpx.Response(
        200,
        headers={
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
            "server": "Apache/2.2.15 (CentOS)",
            "x-powered-by": "PHP/5.3.3",
        },
        request=httpx.Request("GET", "https://t.example"),
    )
    findings = _run("https://t.example", response)
    banner = [f for f in findings if f.type == "info-disclosure-server-banner"]
    assert len(banner) == 2
    assert {b.parameter for b in banner} == {"header:server", "header:x-powered-by"}


def test_fingerprint_is_stable_and_distinct_between_types() -> None:
    response = httpx.Response(200, headers={}, request=httpx.Request("GET", "https://t.example"))
    findings = _run("https://t.example", response)
    fingerprints = {f.fingerprint() for f in findings}
    # No collisions across distinct types.
    assert len(fingerprints) == len(findings)


@pytest.mark.parametrize("severity", list(Severity))
def test_severity_enum_serialises(severity: Severity) -> None:
    assert severity.value in {"info", "low", "medium", "high", "critical"}

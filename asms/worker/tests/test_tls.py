"""Tests for the TLS check.

We never touch the network — every test patches ``asms_worker.checks.tls._handshake``
to feed deterministic fake certificate dicts.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from asms_worker.checks import tls as tls_mod
from asms_worker.checks.base import CheckContext


def _fake_cert(
    *,
    subject_cn: str = "example.com",
    issuer_cn: str = "Let's Encrypt R3",
    sans: tuple[str, ...] = ("example.com", "*.example.com"),
    expires_in_days: int = 60,
) -> dict:
    not_after = datetime.now(timezone.utc) + timedelta(days=expires_in_days)
    return {
        "subject": ((("commonName", subject_cn),),),
        "issuer": ((("commonName", issuer_cn),),),
        "subjectAltName": tuple(("DNS", s) for s in sans),
        "notAfter": not_after.strftime("%b %e %H:%M:%S %Y GMT"),
    }


def _patch_handshake(monkeypatch, cert, protocol="TLSv1.3", error=None):
    monkeypatch.setattr(
        tls_mod, "_handshake", lambda host, port, timeout: (cert, protocol, error)
    )


def test_clean_cert_emits_no_findings(monkeypatch):
    _patch_handshake(monkeypatch, _fake_cert(expires_in_days=180))
    findings = list(
        tls_mod.TLSCheck().run(CheckContext(url="https://example.com/"))
    )
    assert findings == []


def test_expired_cert_is_critical(monkeypatch):
    _patch_handshake(monkeypatch, _fake_cert(expires_in_days=-3))
    types = {f.type for f in tls_mod.TLSCheck().run(CheckContext(url="https://example.com/"))}
    assert "tls-cert-expired" in types


def test_expiring_soon_is_high(monkeypatch):
    _patch_handshake(monkeypatch, _fake_cert(expires_in_days=10))
    findings = list(
        tls_mod.TLSCheck().run(CheckContext(url="https://example.com/"))
    )
    short = [f for f in findings if f.type == "tls-cert-expiring-soon"]
    assert len(short) == 1
    assert short[0].severity.value == "high"


def test_expiring_warning_is_low(monkeypatch):
    _patch_handshake(monkeypatch, _fake_cert(expires_in_days=60))
    findings = list(
        tls_mod.TLSCheck().run(CheckContext(url="https://example.com/"))
    )
    warn = [f for f in findings if f.type == "tls-cert-expiring-warning"]
    assert len(warn) == 1
    assert warn[0].severity.value == "low"


def test_hostname_mismatch(monkeypatch):
    cert = _fake_cert(sans=("other.example",), expires_in_days=180)
    _patch_handshake(monkeypatch, cert)
    types = {f.type for f in tls_mod.TLSCheck().run(CheckContext(url="https://example.com/"))}
    assert "tls-hostname-mismatch" in types


def test_wildcard_san_matches(monkeypatch):
    cert = _fake_cert(sans=("*.example.com",), expires_in_days=180)
    _patch_handshake(monkeypatch, cert)
    types = {
        f.type
        for f in tls_mod.TLSCheck().run(CheckContext(url="https://foo.example.com/"))
    }
    assert "tls-hostname-mismatch" not in types


def test_self_signed_flagged(monkeypatch):
    cert = _fake_cert(subject_cn="self.example", issuer_cn="self.example", expires_in_days=180)
    _patch_handshake(monkeypatch, cert)
    types = {f.type for f in tls_mod.TLSCheck().run(CheckContext(url="https://self.example/"))}
    assert "tls-cert-self-signed" in types


def test_deprecated_protocol_flagged(monkeypatch):
    _patch_handshake(
        monkeypatch, _fake_cert(expires_in_days=180), protocol="TLSv1"
    )
    types = {f.type for f in tls_mod.TLSCheck().run(CheckContext(url="https://example.com/"))}
    assert "tls-deprecated-protocol" in types


def test_handshake_failure_emits_finding(monkeypatch):
    _patch_handshake(monkeypatch, None, protocol="", error="connection refused")
    findings = list(
        tls_mod.TLSCheck().run(CheckContext(url="https://example.com/"))
    )
    assert len(findings) == 1
    assert findings[0].type == "tls-handshake-failed"


def test_no_host_is_noop():
    findings = list(tls_mod.TLSCheck().run(CheckContext(url="not-a-url")))
    assert findings == []


@pytest.mark.parametrize(
    "fingerprint_a,fingerprint_b,expected_equal",
    [
        # Same asset, same finding type, same URL/parameter -> same fingerprint.
        (("asset-1", "tls-cert-expired", "https://x", "GET", "tls:expiry"),
         ("asset-1", "tls-cert-expired", "https://x", "GET", "tls:expiry"), True),
        # Different finding types collide-free.
        (("asset-1", "tls-cert-expired", "https://x", "GET", "tls:expiry"),
         ("asset-1", "tls-cert-self-signed", "https://x", "GET", "tls:issuer"), False),
    ],
)
def test_fingerprint_helper_is_deterministic(fingerprint_a, fingerprint_b, expected_equal):
    """Sanity check that the Finding fingerprint is stable across instances."""
    from asms_worker.checks.base import Finding, Severity

    fa = Finding(
        type=fingerprint_a[1], title="", description="", severity=Severity.LOW,
        url=fingerprint_a[2], http_method=fingerprint_a[3], parameter=fingerprint_a[4],
        asset_id=fingerprint_a[0],
    )
    fb = Finding(
        type=fingerprint_b[1], title="", description="", severity=Severity.LOW,
        url=fingerprint_b[2], http_method=fingerprint_b[3], parameter=fingerprint_b[4],
        asset_id=fingerprint_b[0],
    )
    assert (fa.fingerprint() == fb.fingerprint()) is expected_equal

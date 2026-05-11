"""Tests for the EASM DNS check.

We fake out the resolver entirely so the tests never hit real DNS.
"""

from __future__ import annotations

from dataclasses import dataclass

from asms_worker.checks.base import CheckContext
from asms_worker.checks.dns_records import DNSCheck


@dataclass
class _Rdata:
    text: str

    @property
    def strings(self):
        return (self.text.encode("utf-8"),)

    def __str__(self) -> str:
        return self.text


class _FakeResolver:
    def __init__(self, records: dict[tuple[str, str], list[str]] | None = None):
        self.records = records or {}
        self.timeout = 5.0
        self.lifetime = 5.0

    def resolve(self, name: str, rtype: str):
        key = (name.lower(), rtype.upper())
        if key not in self.records:
            raise RuntimeError("NXDOMAIN")
        return [_Rdata(r) for r in self.records[key]]


def _run(records):
    resolver = _FakeResolver(records)
    return list(
        DNSCheck(resolver=resolver).run(CheckContext(url="https://example.com/"))
    )


def test_no_resolver_at_all_yields_info(monkeypatch):
    # Force the lazy import to fail.
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("dns"):
            raise ImportError("missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    findings = list(DNSCheck().run(CheckContext(url="https://example.com/")))
    assert len(findings) == 1
    assert findings[0].type == "easm-dns-resolver-unavailable"


def test_missing_spf_dmarc_dkim_caa():
    findings = _run({})
    types = {f.type for f in findings}
    assert "dns-missing-spf" in types
    assert "dns-missing-dmarc" in types
    assert "dns-missing-dkim" in types
    assert "dns-missing-caa" in types


def test_permissive_spf_flagged():
    findings = _run({("example.com", "TXT"): ["v=spf1 +all"]})
    types = {f.type for f in findings}
    assert "dns-permissive-spf" in types


def test_strict_spf_does_not_flag_permissive():
    findings = _run({("example.com", "TXT"): ["v=spf1 -all"]})
    types = {f.type for f in findings}
    assert "dns-permissive-spf" not in types


def test_dmarc_monitor_only_flagged():
    findings = _run(
        {
            ("example.com", "TXT"): ["v=spf1 -all"],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none"],
        }
    )
    types = {f.type for f in findings}
    assert "dns-dmarc-monitor-only" in types
    assert "dns-missing-dmarc" not in types


def test_full_clean_only_flags_caa_when_caa_missing():
    findings = _run(
        {
            ("example.com", "TXT"): ["v=spf1 -all"],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
            ("default._domainkey.example.com", "TXT"): ["v=DKIM1; k=rsa; p=…"],
        }
    )
    types = {f.type for f in findings}
    assert types == {"dns-missing-caa"}

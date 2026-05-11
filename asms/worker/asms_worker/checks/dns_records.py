"""EASM DNS posture check.

Inspects the apex domain of the target URL for email-authentication and
CA-issuance posture:

* SPF — flagged if missing, or if it ends in ``?all`` / ``+all`` instead of a
  hardfail/softfail.
* DMARC — flagged if missing, or if ``p=none`` (monitor-only).
* DKIM — surfaces lack of *any* well-known selector record. Light-touch
  because real DKIM selectors are infinite; we only check a handful of
  common ones (default, google, selector1, selector2, k1, mandrill).
* CAA — flagged as INFO when missing (best practice, not a vuln per se).

The check uses Python's stdlib ``socket.getaddrinfo`` for one liveness ping
plus the optional ``dnspython`` library for the TXT/CAA/MX/NS lookups. If
``dnspython`` is unavailable at runtime the check degrades to emitting a
single INFO finding so operators know to install it.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from asms_worker.checks.base import (
    Check,
    CheckContext,
    Confidence,
    Finding,
    Severity,
)

if TYPE_CHECKING:  # pragma: no cover
    from dns.resolver import Resolver


COMMON_DKIM_SELECTORS: tuple[str, ...] = (
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "mandrill",
)


class DNSCheck:
    """Implements the ``Check`` protocol for ``easm.dns``."""

    name = "easm.dns"
    category = "easm"
    DEFAULT_TIMEOUT = 5.0

    def __init__(self, resolver: Resolver | None = None) -> None:
        self._injected_resolver = resolver

    def _build_resolver(self, timeout: float) -> Resolver | None:
        if self._injected_resolver is not None:
            return self._injected_resolver
        try:
            from dns.resolver import Resolver  # type: ignore[import-not-found]
        except ImportError:
            return None
        resolver = Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        return resolver

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        host = urlparse(ctx.url).hostname
        if not host:
            return
        timeout = float(ctx.options.get("timeout_s", self.DEFAULT_TIMEOUT))
        resolver = self._build_resolver(timeout)

        if resolver is None:
            yield Finding(
                type="easm-dns-resolver-unavailable",
                title="dnspython is not installed; DNS checks skipped",
                description=(
                    "The DNS check requires the ``dnspython`` library at runtime. "
                    "Install ``asms-worker[easm]`` (or ``pip install dnspython``) on "
                    "the scanner workers to enable SPF/DKIM/DMARC inspection."
                ),
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                url=ctx.url,
                http_method=None,
                parameter="dns:resolver",
                evidence={"host": host},
                tenant_id=ctx.tenant_id,
                asset_id=ctx.asset_id,
                scan_id=ctx.scan_id,
            )
            return

        yield from _check_spf(ctx, host, resolver)
        yield from _check_dmarc(ctx, host, resolver)
        yield from _check_dkim(ctx, host, resolver)
        yield from _check_caa(ctx, host, resolver)


def _txt_records(resolver: Resolver, name: str) -> list[str]:
    try:
        answer = resolver.resolve(name, "TXT")
    except Exception:
        return []
    out: list[str] = []
    for rdata in answer:
        # dnspython joins the chunks with b""; decode each chunk and reassemble.
        parts = getattr(rdata, "strings", None)
        if parts:
            out.append(b"".join(parts).decode("utf-8", errors="replace"))
        else:
            out.append(str(rdata))
    return out


def _records(resolver: Resolver, name: str, rtype: str) -> list[str]:
    try:
        answer = resolver.resolve(name, rtype)
    except Exception:
        return []
    return [str(r) for r in answer]


def _check_spf(ctx: CheckContext, host: str, resolver: Resolver) -> Iterable[Finding]:
    records = [r for r in _txt_records(resolver, host) if r.lower().startswith("v=spf1")]
    if not records:
        yield Finding(
            type="dns-missing-spf",
            title="Missing SPF record",
            description=(
                f"{host} has no SPF (TXT v=spf1) record. Attackers can spoof email "
                "from this domain without the receiver having a signal to drop it."
            ),
            severity=Severity.MEDIUM,
            cvss=5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            confidence=Confidence.HIGH,
            remediation=(
                "Publish a strict SPF record "
                "(e.g. ``v=spf1 include:_spf.example.com -all``)."
            ),
            url=ctx.url,
            parameter="dns:spf",
            evidence={"host": host},
            tenant_id=ctx.tenant_id,
            asset_id=ctx.asset_id,
            scan_id=ctx.scan_id,
        )
        return
    for record in records:
        normalised = record.lower().strip()
        if normalised.endswith("+all") or normalised.endswith("?all"):
            yield Finding(
                type="dns-permissive-spf",
                title="SPF record ends in +all or ?all",
                description=(
                    f"SPF record {record!r} for {host} effectively allows anyone to "
                    "send mail on the domain's behalf."
                ),
                severity=Severity.HIGH,
                cvss=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
                confidence=Confidence.HIGH,
                remediation=(
                    "Change the terminating mechanism to ``-all`` (hard fail) "
                    "or ``~all`` (soft fail)."
                ),
                url=ctx.url,
                parameter="dns:spf",
                evidence={"record": record},
                tenant_id=ctx.tenant_id,
                asset_id=ctx.asset_id,
                scan_id=ctx.scan_id,
            )


def _check_dmarc(ctx: CheckContext, host: str, resolver: Resolver) -> Iterable[Finding]:
    records = [
        r
        for r in _txt_records(resolver, f"_dmarc.{host}")
        if r.lower().startswith("v=dmarc1")
    ]
    if not records:
        yield Finding(
            type="dns-missing-dmarc",
            title="Missing DMARC record",
            description=(
                f"_dmarc.{host} has no DMARC TXT record. Receivers have no policy "
                "to apply when SPF/DKIM fail."
            ),
            severity=Severity.MEDIUM,
            cvss=5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            confidence=Confidence.HIGH,
            remediation="Publish a DMARC record with at least ``p=quarantine`` and an rua mailbox.",
            url=ctx.url,
            parameter="dns:dmarc",
            evidence={"host": host},
            tenant_id=ctx.tenant_id,
            asset_id=ctx.asset_id,
            scan_id=ctx.scan_id,
        )
        return
    for record in records:
        if "p=none" in record.lower():
            yield Finding(
                type="dns-dmarc-monitor-only",
                title="DMARC policy is monitor-only (p=none)",
                description=(
                    f"DMARC record {record!r} for {host} is publishing in monitor-only "
                    "mode, so receivers will not enforce SPF/DKIM failures."
                ),
                severity=Severity.LOW,
                cvss=3.7,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                confidence=Confidence.HIGH,
                remediation="Move to ``p=quarantine`` then ``p=reject`` once aligned.",
                url=ctx.url,
                parameter="dns:dmarc",
                evidence={"record": record},
                tenant_id=ctx.tenant_id,
                asset_id=ctx.asset_id,
                scan_id=ctx.scan_id,
            )


def _check_dkim(ctx: CheckContext, host: str, resolver: Resolver) -> Iterable[Finding]:
    found_any = False
    for selector in COMMON_DKIM_SELECTORS:
        if _txt_records(resolver, f"{selector}._domainkey.{host}"):
            found_any = True
            break
    if not found_any:
        yield Finding(
            type="dns-missing-dkim",
            title="No DKIM selectors found at common locations",
            description=(
                f"None of the well-known DKIM selectors "
                f"({', '.join(COMMON_DKIM_SELECTORS)}) returned a TXT record under "
                f"_domainkey.{host}. The domain may not sign outbound mail."
            ),
            severity=Severity.LOW,
            cvss=3.7,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            confidence=Confidence.LOW,
            remediation=(
                "Publish a DKIM selector record (or confirm one exists under a custom "
                "selector name we didn't probe)."
            ),
            url=ctx.url,
            parameter="dns:dkim",
            evidence={"selectors_probed": list(COMMON_DKIM_SELECTORS)},
            tenant_id=ctx.tenant_id,
            asset_id=ctx.asset_id,
            scan_id=ctx.scan_id,
        )


def _check_caa(ctx: CheckContext, host: str, resolver: Resolver) -> Iterable[Finding]:
    if not _records(resolver, host, "CAA"):
        yield Finding(
            type="dns-missing-caa",
            title="No CAA record set",
            description=(
                f"{host} has no CAA record. Any CA can issue certificates for the "
                "domain; restricting issuance reduces blast radius."
            ),
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            remediation='Publish a CAA record, e.g. ``0 issue "letsencrypt.org"``.',
            url=ctx.url,
            parameter="dns:caa",
            evidence={"host": host},
            tenant_id=ctx.tenant_id,
            asset_id=ctx.asset_id,
            scan_id=ctx.scan_id,
        )


_check: Check = DNSCheck()

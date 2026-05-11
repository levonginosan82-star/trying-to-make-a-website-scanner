"""Technology / version disclosure check.

Performs a single HTTP request and classifies the response for fingerprints
that disclose specific framework versions known to have public CVEs (PHP,
nginx, Apache, IIS, Tomcat, …). Disclosure on its own isn't necessarily a
critical bug, but the platform's policy is to surface it because:

1. it makes targeted attacks much cheaper, and
2. it usually correlates with un-patched dependencies in CI/CD.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

import httpx

from asms_worker.checks.base import (
    Check,
    CheckContext,
    Confidence,
    Finding,
    Severity,
)

# (header, regex, friendly product name).
PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("server", re.compile(r"^Apache/?\s*([\d.]+)", re.I), "Apache HTTP Server"),
    ("server", re.compile(r"^nginx/?\s*([\d.]+)", re.I), "nginx"),
    ("server", re.compile(r"^Microsoft-IIS/?\s*([\d.]+)", re.I), "Microsoft IIS"),
    ("server", re.compile(r"^Apache-Coyote/?\s*([\d.]+)", re.I), "Apache Tomcat"),
    ("x-powered-by", re.compile(r"^PHP/?\s*([\d.]+)", re.I), "PHP"),
    ("x-powered-by", re.compile(r"^ASP\.NET\s*([\d.]*)", re.I), "ASP.NET"),
    ("x-powered-by", re.compile(r"^Express", re.I), "Express.js"),
    ("x-aspnet-version", re.compile(r"([\d.]+)"), "ASP.NET runtime"),
    ("x-aspnetmvc-version", re.compile(r"([\d.]+)"), "ASP.NET MVC"),
)


class TechDisclosureCheck:
    """Implements the ``Check`` protocol for ``dast.tech_disclosure``."""

    name = "dast.tech_disclosure"
    category = "dast"
    DEFAULT_TIMEOUT = 10.0

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        timeout = float(ctx.options.get("timeout_s", self.DEFAULT_TIMEOUT))
        client = ctx.client or httpx.Client(
            follow_redirects=True,
            timeout=timeout,
            headers={"User-Agent": "ASMS/0.1 (+https://asms.local)"},
        )
        try:
            try:
                response = client.request(ctx.method, ctx.url)
            except httpx.HTTPError as exc:
                yield Finding(
                    type="tech-fetch-failed",
                    title="Could not fetch target for technology fingerprinting",
                    description=f"HTTP request to {ctx.url} failed: {exc}",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    url=ctx.url,
                    http_method=ctx.method,
                    parameter="tech:fetch",
                    evidence={"error": str(exc)},
                    tenant_id=ctx.tenant_id,
                    asset_id=ctx.asset_id,
                    scan_id=ctx.scan_id,
                )
                return

            for header_name, regex, product in PATTERNS:
                value = response.headers.get(header_name)
                if not value:
                    continue
                match = regex.search(value)
                if not match:
                    continue
                version = match.group(1) if match.groups() else ""
                yield Finding(
                    type="tech-version-disclosure",
                    title=f"{product} version disclosed in response headers",
                    description=(
                        f"The response from {ctx.url} discloses {product} "
                        f"{'version ' + version if version else 'usage'} via the "
                        f"`{header_name}` header. Attackers can match this against "
                        "public CVE feeds to target known vulnerabilities."
                    ),
                    severity=Severity.LOW,
                    cvss=3.7,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    confidence=Confidence.CONFIRMED,
                    remediation=(
                        f"Strip or anonymise the `{header_name}` header at the reverse "
                        "proxy / WAF (e.g. `server_tokens off;` in nginx, `ServerTokens "
                        "Prod` + `ServerSignature Off` in Apache)."
                    ),
                    url=ctx.url,
                    http_method=ctx.method,
                    parameter=f"header:{header_name}",
                    evidence={
                        "status_code": response.status_code,
                        "header_value": value,
                        "matched_product": product,
                        "matched_version": version,
                    },
                    tenant_id=ctx.tenant_id,
                    asset_id=ctx.asset_id,
                    scan_id=ctx.scan_id,
                )
        finally:
            if ctx.client is None:
                client.close()


_check: Check = TechDisclosureCheck()

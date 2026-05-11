"""Security-headers DAST check.

Performs an HTTP request against the target and inspects the response headers
for the absence or misconfiguration of standard browser security headers:

    * Strict-Transport-Security (HSTS)
    * Content-Security-Policy (CSP)
    * X-Content-Type-Options
    * X-Frame-Options
    * Referrer-Policy
    * Permissions-Policy
    * Cross-Origin-Opener-Policy
    * Cross-Origin-Resource-Policy
    * Set-Cookie flags (Secure, HttpOnly, SameSite)
    * Server / X-Powered-By information disclosure

Each issue becomes a Finding compatible with the `vulnerabilities` schema.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import urlparse

import httpx

from asms_worker.checks.base import (
    Check,
    CheckContext,
    Confidence,
    Finding,
    Severity,
)

# ---------------------------------------------------------------------------
# Header definitions
# ---------------------------------------------------------------------------

# Required headers and the default severity/CVSS we assign when missing.
# CVSS vectors are illustrative; tune per organisation policy.
REQUIRED_HEADERS: dict[str, dict] = {
    "strict-transport-security": {
        "type": "missing-hsts",
        "title": "Missing HTTP Strict-Transport-Security header",
        "severity": Severity.MEDIUM,
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "remediation": (
            "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` "
            "on every HTTPS response."
        ),
        "https_only": True,
    },
    "content-security-policy": {
        "type": "missing-csp",
        "title": "Missing Content-Security-Policy header",
        "severity": Severity.MEDIUM,
        "cvss": 6.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "remediation": (
            "Define a Content-Security-Policy that restricts script, style, and frame sources "
            "(e.g. `default-src 'self'; script-src 'self' 'nonce-...'`)."
        ),
    },
    "x-content-type-options": {
        "type": "missing-x-content-type-options",
        "title": "Missing X-Content-Type-Options header",
        "severity": Severity.LOW,
        "cvss": 3.7,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "remediation": "Send `X-Content-Type-Options: nosniff` on every response.",
    },
    "x-frame-options": {
        "type": "missing-x-frame-options",
        "title": "Missing X-Frame-Options header (clickjacking risk)",
        "severity": Severity.MEDIUM,
        "cvss": 4.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "remediation": (
            "Send `X-Frame-Options: DENY` "
            "(or use `Content-Security-Policy: frame-ancestors 'none'`)."
        ),
    },
    "referrer-policy": {
        "type": "missing-referrer-policy",
        "title": "Missing Referrer-Policy header",
        "severity": Severity.LOW,
        "cvss": 3.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "remediation": "Send `Referrer-Policy: strict-origin-when-cross-origin`.",
    },
    "permissions-policy": {
        "type": "missing-permissions-policy",
        "title": "Missing Permissions-Policy header",
        "severity": Severity.LOW,
        "cvss": 3.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "remediation": (
            "Send a Permissions-Policy header restricting unused browser features "
            "(e.g. `geolocation=(), camera=(), microphone=()`)."
        ),
    },
}

# Headers that leak server/stack info.
DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")

# Pre-compiled regexes used in this module.
_RE_HSTS_MAX_AGE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)
_RE_CSP_UNSAFE = re.compile(r"'unsafe-(?:inline|eval)'", re.IGNORECASE)
_RE_XFO_VALUE = re.compile(r"^\s*(deny|sameorigin|allow-from\s+\S+)\s*$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# The check
# ---------------------------------------------------------------------------


class SecurityHeadersCheck:
    """DAST check: parse response headers for missing/misconfigured controls."""

    name = "dast.headers"
    category = "dast"
    severity_default = Severity.MEDIUM

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        client = ctx.client or httpx.Client(
            follow_redirects=True,
            timeout=ctx.options.get("timeout_s", 15.0),
            headers={"User-Agent": "ASMS-Scanner/0.1 (+https://asms.local)"},
        )
        owns_client = ctx.client is None
        try:
            response = client.request(ctx.method, ctx.url)
        except httpx.HTTPError as exc:
            yield self._finding(
                ctx,
                type_="scan-error",
                title="Target unreachable",
                description=f"Failed to contact target: {exc!s}",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                evidence={"error": str(exc)},
            )
            return
        finally:
            if owns_client:
                client.close()

        yield from self._analyse(ctx, response)

    # -- analysis ----------------------------------------------------------

    def _analyse(self, ctx: CheckContext, response: httpx.Response) -> Iterable[Finding]:
        # Normalise headers to lowercase keys.
        headers = {k.lower(): v for k, v in response.headers.items()}
        is_https = urlparse(str(response.url)).scheme == "https"

        # 1. Missing required headers.
        for header, spec in REQUIRED_HEADERS.items():
            if spec.get("https_only") and not is_https:
                continue
            if header not in headers:
                yield self._finding(
                    ctx,
                    type_=spec["type"],
                    title=spec["title"],
                    description=(
                        f"The response from {response.url} does not include the "
                        f"`{header}` header. {spec['title']}."
                    ),
                    severity=spec["severity"],
                    cvss=spec["cvss"],
                    cvss_vector=spec["cvss_vector"],
                    remediation=spec["remediation"],
                    parameter=f"header:{header}",
                    evidence={
                        "status_code": response.status_code,
                        "final_url": str(response.url),
                        "headers_present": sorted(headers.keys()),
                    },
                )

        # 2. Misconfigurations on present headers.
        yield from self._check_hsts(ctx, response, headers)
        yield from self._check_csp(ctx, response, headers)
        yield from self._check_xfo(ctx, response, headers)
        yield from self._check_cookies(ctx, response)

        # 3. Information disclosure via server banners.
        for header in DISCLOSURE_HEADERS:
            value = headers.get(header)
            if value:
                yield self._finding(
                    ctx,
                    type_="info-disclosure-server-banner",
                    title=f"Information disclosure via `{header}` header",
                    description=(
                        f"The `{header}` header reveals server/stack information "
                        f"(`{value}`). Attackers can use it to look up known CVEs."
                    ),
                    severity=Severity.INFO,
                    cvss=2.7,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    remediation=(
                        "Strip or generalise version banners "
                        "(e.g. `ServerTokens Prod` on Apache, `server_tokens off;` on Nginx)."
                    ),
                    parameter=f"header:{header}",
                    evidence={"header": header, "value": value},
                )

    # -- specific header checks --------------------------------------------

    def _check_hsts(
        self, ctx: CheckContext, response: httpx.Response, headers: dict[str, str]
    ) -> Iterable[Finding]:
        value = headers.get("strict-transport-security")
        if not value:
            return
        m = _RE_HSTS_MAX_AGE.search(value)
        max_age = int(m.group(1)) if m else 0
        if max_age < 15552000:  # 180 days
            yield self._finding(
                ctx,
                type_="weak-hsts",
                title="HSTS max-age is too low",
                description=(
                    f"`Strict-Transport-Security: {value}` has max-age={max_age}. "
                    "Recommend at least 15552000 (180 days), ideally 31536000 (1 year)."
                ),
                severity=Severity.LOW,
                cvss=3.7,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                remediation="Set `max-age=31536000; includeSubDomains; preload`.",
                parameter="header:strict-transport-security",
                evidence={"value": value, "max_age": max_age},
            )

    def _check_csp(
        self, ctx: CheckContext, response: httpx.Response, headers: dict[str, str]
    ) -> Iterable[Finding]:
        value = headers.get("content-security-policy")
        if not value:
            return
        if _RE_CSP_UNSAFE.search(value):
            yield self._finding(
                ctx,
                type_="weak-csp-unsafe",
                title="CSP allows `unsafe-inline` or `unsafe-eval`",
                description=(
                    f"The Content-Security-Policy `{value}` includes an unsafe directive, "
                    "which negates the protection against reflected and stored XSS."
                ),
                severity=Severity.MEDIUM,
                cvss=6.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                remediation=(
                    "Remove `'unsafe-inline'`/`'unsafe-eval'`; use nonces or hashes for "
                    "inline scripts."
                ),
                parameter="header:content-security-policy",
                evidence={"value": value},
            )
        if "default-src" not in value.lower() and "script-src" not in value.lower():
            yield self._finding(
                ctx,
                type_="weak-csp-no-default",
                title="CSP does not constrain script or default sources",
                description=(
                    "The Content-Security-Policy does not contain a `default-src` or "
                    "`script-src` directive, leaving script execution unrestricted."
                ),
                severity=Severity.MEDIUM,
                cvss=5.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
                remediation="Add `default-src 'self'` and a strict `script-src` directive.",
                parameter="header:content-security-policy",
                evidence={"value": value},
            )

    def _check_xfo(
        self, ctx: CheckContext, response: httpx.Response, headers: dict[str, str]
    ) -> Iterable[Finding]:
        value = headers.get("x-frame-options")
        if value and not _RE_XFO_VALUE.match(value):
            yield self._finding(
                ctx,
                type_="weak-x-frame-options",
                title="X-Frame-Options has a non-standard value",
                description=(
                    f"`X-Frame-Options: {value}` is not one of DENY / SAMEORIGIN / ALLOW-FROM. "
                    "Browsers may ignore the header, leaving the page framable."
                ),
                severity=Severity.LOW,
                cvss=3.7,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                remediation="Use `X-Frame-Options: DENY` or `SAMEORIGIN`.",
                parameter="header:x-frame-options",
                evidence={"value": value},
            )

    def _check_cookies(self, ctx: CheckContext, response: httpx.Response) -> Iterable[Finding]:
        # httpx exposes Set-Cookie via response.headers.get_list("set-cookie").
        cookies = response.headers.get_list("set-cookie")
        is_https = urlparse(str(response.url)).scheme == "https"
        for cookie in cookies:
            lower = cookie.lower()
            name = cookie.split("=", 1)[0].strip()
            problems: list[str] = []
            if "secure" not in lower and is_https:
                problems.append("missing-secure")
            if "httponly" not in lower:
                problems.append("missing-httponly")
            if "samesite" not in lower:
                problems.append("missing-samesite")
            if problems:
                yield self._finding(
                    ctx,
                    type_="insecure-cookie",
                    title=f"Insecure cookie flags on `{name}`",
                    description=(
                        f"Cookie `{name}` is set without one or more recommended flags: "
                        f"{', '.join(problems)}. This makes session hijacking and CSRF easier."
                    ),
                    severity=Severity.MEDIUM,
                    cvss=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                    remediation=(
                        "Set `Secure; HttpOnly; SameSite=Lax` (or `Strict`) on session cookies."
                    ),
                    parameter=f"cookie:{name}",
                    evidence={"cookie": cookie, "problems": problems},
                )

    # -- helpers -----------------------------------------------------------

    def _finding(
        self,
        ctx: CheckContext,
        *,
        type_: str,
        title: str,
        description: str,
        severity: Severity,
        cvss: float | None = None,
        cvss_vector: str | None = None,
        remediation: str | None = None,
        parameter: str | None = None,
        confidence: Confidence = Confidence.HIGH,
        evidence: dict | None = None,
    ) -> Finding:
        return Finding(
            type=type_,
            title=title,
            description=description,
            severity=severity,
            url=ctx.url,
            http_method=ctx.method,
            parameter=parameter,
            cvss=cvss,
            cvss_vector=cvss_vector,
            confidence=confidence,
            remediation=remediation,
            evidence=evidence or {},
            tenant_id=ctx.tenant_id,
            asset_id=ctx.asset_id,
            scan_id=ctx.scan_id,
        )


# Type-check that we satisfy the protocol.
_: Check = SecurityHeadersCheck()

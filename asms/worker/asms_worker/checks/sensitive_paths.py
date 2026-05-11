"""Sensitive-paths probe.

Performs a small, deterministic list of GET requests for files that should
never be reachable from the public internet (``.git/HEAD``, ``.env``,
``.DS_Store``, backups, etc.). The probe is intentionally conservative — it
sends fewer than ~30 requests per scan, uses the worker's existing
``httpx.Client``, and only flags a finding when the response body looks like
the real artefact (not a generic 404 page that happens to return 200).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

from asms_worker.checks.base import (
    Check,
    CheckContext,
    Confidence,
    Finding,
    Severity,
)


@dataclass(frozen=True)
class _Probe:
    path: str
    type_: str
    title: str
    severity: Severity
    cvss: float
    cvss_vector: str
    # Substring (case-insensitive) that must appear in the response body to
    # consider the artefact real. Avoids false positives from soft-404 pages.
    signature: str
    remediation: str


# Carefully curated — every probe is high-signal. Adding more without
# signatures will flood the dashboard with false positives.
PROBES: tuple[_Probe, ...] = (
    _Probe(
        path=".git/HEAD",
        type_="exposed-git-repo",
        title="Exposed .git/ repository",
        severity=Severity.CRITICAL,
        cvss=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        signature="ref: refs/",
        remediation=(
            "Remove the .git/ directory from the document root and configure the web "
            "server to deny hidden dot-directories."
        ),
    ),
    _Probe(
        path=".env",
        type_="exposed-env-file",
        title="Exposed .env file with secrets",
        severity=Severity.CRITICAL,
        cvss=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        signature="=",  # any KEY=VALUE pair
        remediation=(
            "Move secrets out of the document root (or out of the container's working "
            "directory) and serve them via a secret manager."
        ),
    ),
    _Probe(
        path=".DS_Store",
        type_="exposed-ds-store",
        title="Exposed macOS .DS_Store file",
        severity=Severity.LOW,
        cvss=3.7,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        signature="Bud1",  # magic bytes of a .DS_Store file
        remediation="Delete .DS_Store files from the deploy artefact and add them to .gitignore.",
    ),
    _Probe(
        path="wp-config.php.bak",
        type_="exposed-wp-config-backup",
        title="Exposed WordPress wp-config backup",
        severity=Severity.CRITICAL,
        cvss=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        signature="DB_PASSWORD",
        remediation="Delete the backup and serve wp-config.php via PHP only.",
    ),
    _Probe(
        path="phpinfo.php",
        type_="phpinfo-disclosure",
        title="Public phpinfo() page",
        severity=Severity.MEDIUM,
        cvss=5.3,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        signature="PHP Version",
        remediation="Remove phpinfo.php from production.",
    ),
    _Probe(
        path="server-status",
        type_="apache-server-status",
        title="Apache server-status exposed",
        severity=Severity.MEDIUM,
        cvss=5.3,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        signature="Apache Server Status",
        remediation="Restrict /server-status to localhost in the Apache config.",
    ),
    _Probe(
        path="actuator/env",
        type_="spring-actuator-env",
        title="Spring Boot actuator /env exposed",
        severity=Severity.HIGH,
        cvss=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        signature="propertySources",
        remediation=(
            "Disable management.endpoint.env or restrict actuator endpoints via "
            "Spring Security."
        ),
    ),
)


class SensitivePathsCheck:
    """Implements the ``Check`` protocol for ``dast.sensitive_paths``."""

    name = "dast.sensitive_paths"
    category = "dast"
    DEFAULT_TIMEOUT = 10.0

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        timeout = float(ctx.options.get("timeout_s", self.DEFAULT_TIMEOUT))
        base = _normalised_base(ctx.url)
        if not base:
            return

        client = ctx.client or httpx.Client(
            follow_redirects=False,
            timeout=timeout,
            headers={"User-Agent": "ASMS/0.1 (+https://asms.local)"},
        )
        try:
            for probe in PROBES:
                target = urljoin(base, probe.path)
                try:
                    response = client.get(target)
                except httpx.HTTPError:
                    continue
                if response.status_code != 200:
                    continue
                body = response.text[:8192]  # cap evidence + signature check
                if probe.signature.lower() not in body.lower():
                    continue
                yield Finding(
                    type=probe.type_,
                    title=probe.title,
                    description=(
                        f"{target} returned 200 OK and the response body contains the "
                        f"expected signature ({probe.signature!r}), confirming the "
                        "artefact is actually served and not a generic 404 page."
                    ),
                    severity=probe.severity,
                    cvss=probe.cvss,
                    cvss_vector=probe.cvss_vector,
                    confidence=Confidence.CONFIRMED,
                    remediation=probe.remediation,
                    url=target,
                    http_method="GET",
                    parameter=f"path:{probe.path}",
                    evidence={
                        "status_code": response.status_code,
                        "content_length": len(response.content),
                        "signature": probe.signature,
                    },
                    tenant_id=ctx.tenant_id,
                    asset_id=ctx.asset_id,
                    scan_id=ctx.scan_id,
                )
        finally:
            if ctx.client is None:
                client.close()


def _normalised_base(url: str) -> str | None:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return None
    # Force trailing slash so urljoin treats it as a directory.
    path = parsed.path or "/"
    if not path.endswith("/"):
        path = path.rsplit("/", 1)[0] + "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


_check: Check = SensitivePathsCheck()

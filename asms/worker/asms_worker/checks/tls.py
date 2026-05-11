"""TLS / SSL posture check.

Connects to the target host on its TLS port (default 443), retrieves the
peer certificate, and yields findings for:

* expired certificates (critical)
* certificates expiring within 30 days (high) or 90 days (medium)
* hostname mismatch on the SAN list (high)
* self-signed certificates (high)
* deprecated TLS protocol versions negotiated (high) — i.e. TLS 1.0/1.1.

The check is intentionally read-only: it performs a single TLS handshake
and a `getpeercert()` call. It never sends application data, never sends
weak ciphers itself, and does not connect to any host other than the one
named in the target URL.
"""

from __future__ import annotations

import socket
import ssl
from collections.abc import Iterable
from datetime import datetime, timezone
from urllib.parse import urlparse

from asms_worker.checks.base import (
    Check,
    CheckContext,
    Confidence,
    Finding,
    Severity,
)

DEPRECATED_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}


class TLSCheck:
    """Implements the ``Check`` protocol for ``dast.tls``."""

    name = "dast.tls"
    category = "dast"

    # Default to the timeout the rest of the worker uses; can be overridden via
    # ctx.options["timeout_s"].
    DEFAULT_TIMEOUT = 10.0

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        parsed = urlparse(ctx.url)
        host = parsed.hostname
        if not host:
            return
        port = parsed.port or (443 if parsed.scheme == "https" else 443)
        timeout = float(ctx.options.get("timeout_s", self.DEFAULT_TIMEOUT))

        # Always try the modern handshake first; if that fails fall back to
        # the permissive context so we can still surface the failure as a
        # finding rather than an exception.
        cert, negotiated, error = _handshake(host, port, timeout)
        if error is not None:
            yield Finding(
                type="tls-handshake-failed",
                title="TLS handshake failed",
                description=(
                    f"Could not complete a TLS handshake against {host}:{port}: {error}. "
                    "This may indicate the service does not speak TLS or the certificate "
                    "chain is unreachable."
                ),
                severity=Severity.LOW,
                cvss=3.7,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                confidence=Confidence.HIGH,
                remediation=(
                    "Confirm the service is reachable over TLS, that its certificate "
                    "chain validates, and that it offers at least TLS 1.2."
                ),
                url=ctx.url,
                http_method=ctx.method,
                parameter="tls:handshake",
                evidence={"host": host, "port": port, "error": error},
                tenant_id=ctx.tenant_id,
                asset_id=ctx.asset_id,
                scan_id=ctx.scan_id,
            )
            return

        # Hostname mismatch.
        if cert and not _hostname_matches(cert, host):
            sans = _sans(cert)
            yield Finding(
                type="tls-hostname-mismatch",
                title="TLS certificate does not match target hostname",
                description=(
                    f"The certificate presented by {host}:{port} does not list "
                    f"{host} in its Subject Alternative Name list ({sans!r})."
                ),
                severity=Severity.HIGH,
                cvss=7.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                confidence=Confidence.HIGH,
                remediation=(
                    "Re-issue the certificate to include the hostname clients connect "
                    "to in the SAN list, or update DNS to point at the correct origin."
                ),
                url=ctx.url,
                http_method=ctx.method,
                parameter="tls:san",
                evidence={"host": host, "port": port, "sans": sans},
                tenant_id=ctx.tenant_id,
                asset_id=ctx.asset_id,
                scan_id=ctx.scan_id,
            )

        # Expiry.
        expiry = _not_after(cert)
        if expiry is not None:
            now = datetime.now(timezone.utc)
            days_left = (expiry - now).days
            if days_left < 0:
                yield Finding(
                    type="tls-cert-expired",
                    title="TLS certificate has expired",
                    description=(
                        f"The TLS certificate for {host} expired {abs(days_left)} "
                        "days ago. Clients should be rejecting this site outright."
                    ),
                    severity=Severity.CRITICAL,
                    cvss=9.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                    confidence=Confidence.CONFIRMED,
                    remediation="Renew the certificate immediately and automate rotation.",
                    url=ctx.url,
                    http_method=ctx.method,
                    parameter="tls:expiry",
                    evidence={"host": host, "expires_at": expiry.isoformat()},
                    tenant_id=ctx.tenant_id,
                    asset_id=ctx.asset_id,
                    scan_id=ctx.scan_id,
                )
            elif days_left < 30:
                yield Finding(
                    type="tls-cert-expiring-soon",
                    title="TLS certificate expires in under 30 days",
                    description=(
                        f"The certificate for {host} expires in {days_left} days. "
                        "Outages occur every year because of expired TLS certificates; "
                        "rotate before the deadline."
                    ),
                    severity=Severity.HIGH,
                    cvss=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                    confidence=Confidence.HIGH,
                    remediation=(
                        "Automate certificate renewal (cert-manager, ACME) "
                        "≥30 days before expiry."
                    ),
                    url=ctx.url,
                    http_method=ctx.method,
                    parameter="tls:expiry",
                    evidence={
                        "host": host,
                        "expires_at": expiry.isoformat(),
                        "days_left": days_left,
                    },
                    tenant_id=ctx.tenant_id,
                    asset_id=ctx.asset_id,
                    scan_id=ctx.scan_id,
                )
            elif days_left < 90:
                yield Finding(
                    type="tls-cert-expiring-warning",
                    title="TLS certificate expires in under 90 days",
                    description=(
                        f"The certificate for {host} expires in {days_left} days. "
                        "Schedule rotation before it enters the 30-day warning window."
                    ),
                    severity=Severity.LOW,
                    cvss=3.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                    confidence=Confidence.MEDIUM,
                    remediation="Confirm the renewal pipeline will run well before expiry.",
                    url=ctx.url,
                    http_method=ctx.method,
                    parameter="tls:expiry",
                    evidence={
                        "host": host,
                        "expires_at": expiry.isoformat(),
                        "days_left": days_left,
                    },
                    tenant_id=ctx.tenant_id,
                    asset_id=ctx.asset_id,
                    scan_id=ctx.scan_id,
                )

        # Self-signed: issuer == subject.
        if cert and _is_self_signed(cert):
            yield Finding(
                type="tls-cert-self-signed",
                title="TLS certificate is self-signed",
                description=(
                    f"The certificate presented by {host}:{port} is self-signed. "
                    "Browsers and well-behaved clients will refuse to trust it."
                ),
                severity=Severity.HIGH,
                cvss=7.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                confidence=Confidence.HIGH,
                remediation="Issue a certificate from a public CA (Let's Encrypt, public PKI).",
                url=ctx.url,
                http_method=ctx.method,
                parameter="tls:issuer",
                evidence={"host": host, "issuer": _name(cert, "issuer")},
                tenant_id=ctx.tenant_id,
                asset_id=ctx.asset_id,
                scan_id=ctx.scan_id,
            )

        # Deprecated negotiated protocol.
        if negotiated in DEPRECATED_PROTOCOLS:
            yield Finding(
                type="tls-deprecated-protocol",
                title=f"Deprecated TLS protocol negotiated: {negotiated}",
                description=(
                    f"The handshake negotiated {negotiated}, which is deprecated. "
                    "Disable everything below TLS 1.2 on the server."
                ),
                severity=Severity.HIGH,
                cvss=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                confidence=Confidence.HIGH,
                remediation="Disable TLS 1.0/1.1 and SSLv2/v3 on the server; require TLS 1.2+.",
                url=ctx.url,
                http_method=ctx.method,
                parameter="tls:protocol",
                evidence={"host": host, "negotiated_protocol": negotiated},
                tenant_id=ctx.tenant_id,
                asset_id=ctx.asset_id,
                scan_id=ctx.scan_id,
            )


# ---------- helpers (kept module-level so they're trivially mockable in tests) ----------


def _handshake(host: str, port: int, timeout: float) -> tuple[dict | None, str | None, str | None]:
    """Return (cert_dict, negotiated_protocol, error_string).

    Strategy:
      1. Try a strict handshake first so ``getpeercert()`` returns the full
         subject/issuer/SAN/notAfter dict.
      2. If verification fails (expired, self-signed, hostname mismatch), retry
         with verification disabled so we can still report the protocol version
         — and parse the DER-encoded cert by hand to surface as much detail as
         we can without taking on a dependency on the ``cryptography`` library.
    """
    try:
        strict = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with strict.wrap_socket(raw, server_hostname=host) as wrapped:
                return wrapped.getpeercert(), wrapped.version() or "", None
    except ssl.SSLCertVerificationError as exc:
        # Fall through to permissive handshake so we can still inspect the cert.
        verify_error = str(exc)
    except (OSError, ssl.SSLError) as exc:
        return None, "", str(exc)

    try:
        permissive = ssl.create_default_context()
        permissive.check_hostname = False
        permissive.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with permissive.wrap_socket(raw, server_hostname=host) as wrapped:
                der = wrapped.getpeercert(binary_form=True)
                version = wrapped.version() or ""
        cert = _parse_der_cert(der) if der else None
        if cert is not None:
            cert["_verify_error"] = verify_error
        return cert, version, None
    except (OSError, ssl.SSLError) as exc:
        return None, "", f"{verify_error}; permissive retry failed: {exc}"


def _parse_der_cert(der: bytes) -> dict | None:
    """Parse a DER-encoded X.509 cert using stdlib only.

    Python's ``ssl.PEM_cert_to_DER_cert`` is one-way, but ``_test_decode_cert``
    in the stdlib exposes the decoded dict shape. Use it via a temporary PEM
    file written to disk.
    """
    import tempfile
    from ssl import _ssl  # type: ignore[attr-defined]

    pem = ssl.DER_cert_to_PEM_cert(der)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=True) as fh:
        fh.write(pem)
        fh.flush()
        try:
            return _ssl._test_decode_cert(fh.name)
        except Exception:
            return None


def _sans(cert: dict | None) -> list[str]:
    if not cert:
        return []
    return [val for typ, val in cert.get("subjectAltName", ()) if typ.lower() == "dns"]


def _hostname_matches(cert: dict, host: str) -> bool:
    sans = _sans(cert)
    if not sans:
        # Fall back to CN.
        for rdn in cert.get("subject", ()):
            for key, val in rdn:
                if key == "commonName":
                    sans.append(val)
    host_lower = host.lower()
    for san in sans:
        if san.lower() == host_lower:
            return True
        if san.startswith("*."):
            # *.example.com matches foo.example.com but not example.com.
            suffix = san[1:].lower()
            if host_lower.endswith(suffix) and host_lower.count(".") >= san.count("."):
                return True
    return False


def _not_after(cert: dict | None) -> datetime | None:
    if not cert:
        return None
    raw = cert.get("notAfter")
    if not raw:
        return None
    # Format used by Python's ssl module: 'Sep  5 12:00:00 2025 GMT'
    try:
        return datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _is_self_signed(cert: dict) -> bool:
    return _name(cert, "subject") == _name(cert, "issuer") and _name(cert, "subject") != ""


def _name(cert: dict, key: str) -> str:
    rdns = cert.get(key, ())
    parts: list[str] = []
    for rdn in rdns:
        for k, v in rdn:
            parts.append(f"{k}={v}")
    return ",".join(parts)


_check: Check = TLSCheck()

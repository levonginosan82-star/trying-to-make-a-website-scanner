"""SAST secrets scanner.

Walks a directory tree and yields findings for files that contain anything
matching a curated regex list (AWS keys, GitHub tokens, JWTs, private keys,
generic high-entropy assignments). Designed to be embedded in CI: invoke
``asms-worker scan-secrets --path .`` and let the resulting JSON drive the
existing findings pipeline.

Heuristics are deliberately conservative — the goal is to be useful in CI
(low FP rate) rather than to mimic a full SAST suite.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from asms_worker.checks.base import (
    Check,
    CheckContext,
    Confidence,
    Finding,
    Severity,
)


@dataclass(frozen=True)
class _SecretPattern:
    type_: str
    title: str
    severity: Severity
    cvss: float
    regex: re.Pattern[str]
    remediation: str


PATTERNS: tuple[_SecretPattern, ...] = (
    _SecretPattern(
        type_="leaked-aws-access-key",
        title="AWS access key id committed to repo",
        severity=Severity.CRITICAL,
        cvss=9.8,
        regex=re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        remediation=(
            "Rotate the AWS key, scrub git history, and store secrets in IAM "
            "Roles or AWS Secrets Manager."
        ),
    ),
    _SecretPattern(
        type_="leaked-github-token",
        title="GitHub personal access token committed to repo",
        severity=Severity.CRITICAL,
        cvss=9.1,
        regex=re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,80}\b"),
        remediation=(
            "Revoke the token at https://github.com/settings/tokens and rotate "
            "any dependent automation."
        ),
    ),
    _SecretPattern(
        type_="leaked-slack-token",
        title="Slack bot/user token committed to repo",
        severity=Severity.HIGH,
        cvss=8.1,
        regex=re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,72}\b"),
        remediation=(
            "Revoke the token in the Slack admin panel and use OAuth "
            "installation flow instead."
        ),
    ),
    _SecretPattern(
        type_="leaked-private-key",
        title="Private cryptographic key committed to repo",
        severity=Severity.CRITICAL,
        cvss=9.8,
        regex=re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED |)?PRIVATE KEY-----"
        ),
        remediation=(
            "Rotate the key, re-issue any signed material, and remove from "
            "version control history."
        ),
    ),
    _SecretPattern(
        type_="leaked-jwt",
        title="Hard-coded JSON Web Token in source",
        severity=Severity.HIGH,
        cvss=7.5,
        regex=re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        remediation=(
            "Treat JWTs as bearer credentials — never commit them. Issue "
            "short-lived tokens at runtime."
        ),
    ),
    _SecretPattern(
        type_="leaked-google-api-key",
        title="Google API key committed to repo",
        severity=Severity.HIGH,
        cvss=7.5,
        regex=re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        remediation=(
            "Restrict and rotate the key via Google Cloud Console; consider "
            "HTTP-referrer restrictions."
        ),
    ),
    _SecretPattern(
        type_="leaked-generic-secret-assignment",
        title="High-entropy secret assigned in source",
        severity=Severity.MEDIUM,
        cvss=5.3,
        # No leading \b — we want to match identifiers like DB_PASSWORD, where
        # the underscore is a word char and prevents a boundary before "PASSWORD".
        regex=re.compile(
            r"(?im)(?:api[_-]?key|secret|password|token)\s*[:=]\s*[\"']?([A-Za-z0-9/+=_\-]{20,})"
        ),
        remediation=(
            "Move the value to a secret manager and reference it via "
            "environment variables."
        ),
    ),
)


# File types we never bother to scan.
SKIP_EXTENSIONS: frozenset[str] = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico",
    ".mp3", ".mp4", ".mov", ".webm", ".pdf",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".woff", ".woff2", ".ttf",
    ".pyc", ".class", ".so", ".dll", ".dylib",
})

SKIP_DIRECTORIES: frozenset[str] = frozenset({
    ".git", ".hg", ".svn", "node_modules", "vendor",
    "__pycache__", ".venv", "venv", ".tox", "dist", "build", ".next",
})

# Cap each file at 1 MiB — anything bigger is almost certainly binary / data.
MAX_FILE_BYTES = 1 * 1024 * 1024


class SecretsCheck:
    """Implements the ``Check`` protocol for ``sast.secrets``."""

    name = "sast.secrets"
    category = "sast"

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        """Scan a directory tree rooted at ``ctx.url`` (interpreted as a path)."""
        root = Path(ctx.url).expanduser().resolve()
        if not root.exists():
            return
        if root.is_file():
            yield from _scan_file(ctx, root)
            return
        for path in _iter_files(root):
            yield from _scan_file(ctx, path)


def _iter_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRECTORIES for part in path.parts):
            continue
        if path.suffix.lower() in SKIP_EXTENSIONS:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def _scan_file(ctx: CheckContext, path: Path) -> Iterable[Finding]:
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return
    seen_locations: set[tuple[str, int]] = set()
    for pattern in PATTERNS:
        for match in pattern.regex.finditer(content):
            line_no = content.count("\n", 0, match.start()) + 1
            key = (pattern.type_, line_no)
            if key in seen_locations:
                continue
            seen_locations.add(key)
            snippet = match.group(0)
            redacted = _redact(snippet)
            yield Finding(
                type=pattern.type_,
                title=pattern.title,
                description=(
                    f"{path} line {line_no} contains a value matching the pattern for "
                    f"{pattern.title.lower()}. Redacted preview: {redacted}."
                ),
                severity=pattern.severity,
                cvss=pattern.cvss,
                confidence=Confidence.HIGH,
                remediation=pattern.remediation,
                url=str(path),
                http_method=None,
                parameter=f"line:{line_no}",
                evidence={
                    "path": str(path),
                    "line": line_no,
                    "preview": redacted,
                    "match_length": len(snippet),
                },
                tenant_id=ctx.tenant_id,
                asset_id=ctx.asset_id,
                scan_id=ctx.scan_id,
            )


def _redact(value: str) -> str:
    """Show the first 4 and last 2 chars; mask everything else."""
    if len(value) <= 10:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 6)}{value[-2:]}"


_check: Check = SecretsCheck()

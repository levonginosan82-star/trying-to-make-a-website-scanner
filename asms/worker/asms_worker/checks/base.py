"""Core types shared by every check.

A Check is a unit of scanning logic. It receives a CheckContext (the target
plus an httpx client) and yields zero or more Finding objects. Findings are
later normalised, deduplicated, and persisted by the findings service.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol, runtime_checkable

import httpx


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


@dataclass
class CheckContext:
    """Inputs handed to a check.

    Attributes:
        url: target URL.
        method: HTTP method for HTTP-based checks.
        client: shared httpx client (timeouts, proxy, mTLS already configured).
        tenant_id: organization identifier (forwarded to findings).
        asset_id: asset identifier (forwarded to findings).
        scan_id: scan identifier (forwarded to findings).
        options: free-form, check-specific options.
    """

    url: str
    method: str = "GET"
    client: httpx.Client | None = None
    tenant_id: str | None = None
    asset_id: str | None = None
    scan_id: str | None = None
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """A single normalised finding. Mirrors the `vulnerabilities` SQL row."""

    type: str                          # short machine-friendly id, e.g. "missing-csp"
    title: str
    description: str
    severity: Severity
    url: str | None = None
    http_method: str | None = None
    parameter: str | None = None
    cvss: float | None = None
    cvss_vector: str | None = None
    confidence: Confidence = Confidence.MEDIUM
    remediation: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    tenant_id: str | None = None
    asset_id: str | None = None
    scan_id: str | None = None
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def fingerprint(self) -> str:
        """Stable hash used for deduplication.

        Two findings collide iff they describe the same issue at the same
        location for the same asset.
        """
        raw = "|".join(
            [
                self.asset_id or "",
                self.type,
                self.url or "",
                self.http_method or "",
                self.parameter or "",
            ]
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "url": self.url,
            "http_method": self.http_method,
            "parameter": self.parameter,
            "cvss": self.cvss,
            "cvss_vector": self.cvss_vector,
            "confidence": self.confidence.value,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "tenant_id": self.tenant_id,
            "asset_id": self.asset_id,
            "scan_id": self.scan_id,
            "discovered_at": self.discovered_at.isoformat(),
            "fingerprint": self.fingerprint(),
        }


@runtime_checkable
class Check(Protocol):
    """Every scanner module implements this interface."""

    name: str          # e.g. "dast.headers"
    category: str      # e.g. "dast"

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        ...

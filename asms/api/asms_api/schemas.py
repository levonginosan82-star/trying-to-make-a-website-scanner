"""Pydantic v2 schemas exposed by the API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from asms_api.models import FindingStatus, ScanStatus, Severity


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    type: str
    title: str
    description: str
    severity: Severity
    cvss: float | None = None
    url: str | None = None
    http_method: str | None = None
    parameter: str | None = None
    status: FindingStatus
    asset_id: str
    scan_id: str | None = None
    first_seen_at: datetime
    last_seen_at: datetime


class SecurityScoreOut(BaseModel):
    organization_id: str
    security_score: int = Field(..., ge=0, le=100)
    open_critical: int = 0
    open_high: int = 0
    open_medium: int = 0
    open_low: int = 0
    open_info: int = 0
    fixed_total: int = 0
    false_positive_total: int = 0


class ScanCreate(BaseModel):
    organization_id: str
    asset_id: str
    scan_type: str = Field(default="dast", pattern="^(dast|easm|api|mobile|infra|sast|iac)$")
    config: dict[str, Any] = Field(default_factory=dict)


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    organization_id: str
    asset_id: str
    scan_type: str
    status: ScanStatus
    config: dict[str, Any]
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None

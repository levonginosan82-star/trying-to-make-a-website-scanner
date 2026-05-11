"""SQLAlchemy 2.0 models that mirror asms/db/schema.sql.

We keep these in sync with the SQL schema by hand for now; a migration tool
(Alembic) is out of scope for this PR. SQLite is used for local dev; the same
models work against Postgres because we stick to portable column types.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    WONT_FIX = "wont_fix"


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    assets: Mapped[list[Asset]] = relationship(back_populates="organization")
    vulnerabilities: Mapped[list[Vulnerability]] = relationship(back_populates="organization")


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"))
    asset_type: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(String(500))
    criticality: Mapped[int] = mapped_column(default=3)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    organization: Mapped[Organization] = relationship(back_populates="assets")
    scans: Mapped[list[Scan]] = relationship(back_populates="asset")


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"))
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"))
    scan_type: Mapped[str] = mapped_column(String(32))
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, native_enum=False), default=ScanStatus.QUEUED
    )
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    asset: Mapped[Asset] = relationship(back_populates="scans")
    vulnerabilities: Mapped[list[Vulnerability]] = relationship(back_populates="scan")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"))
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"))
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id"), nullable=True)

    type: Mapped[str] = mapped_column(String(120))
    severity: Mapped[Severity] = mapped_column(Enum(Severity, native_enum=False))
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(200), nullable=True)

    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)

    url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    http_method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    parameter: Mapped[str | None] = mapped_column(String(500), nullable=True)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)

    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus, native_enum=False), default=FindingStatus.OPEN
    )
    fingerprint: Mapped[str] = mapped_column(String(64))

    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=_now, onupdate=func.now()
    )

    organization: Mapped[Organization] = relationship(back_populates="vulnerabilities")
    scan: Mapped[Scan | None] = relationship(back_populates="vulnerabilities")

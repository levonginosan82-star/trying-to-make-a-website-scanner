"""HTTP routes for the ASMS control plane."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from asms_api.db import get_session
from asms_api.models import (
    Asset,
    FindingStatus,
    Organization,
    Scan,
    ScanStatus,
    Severity,
    Vulnerability,
)
from asms_api.schemas import (
    ScanCreate,
    ScanOut,
    SecurityScoreOut,
    VulnerabilityOut,
)
from asms_api.scoring import compute_score

router = APIRouter(prefix="/api/v1")

SessionDep = Annotated[AsyncSession, Depends(get_session)]


async def _resolve_org(session: AsyncSession, identifier: str) -> Organization:
    """Resolve an organization by id OR slug to make the dashboard URL nicer."""
    stmt = select(Organization).where(
        (Organization.id == identifier) | (Organization.slug == identifier)
    )
    org = (await session.execute(stmt)).scalar_one_or_none()
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"organization {identifier!r} not found"
        )
    return org


@router.get(
    "/organizations/{org_identifier}/security-score", response_model=SecurityScoreOut
)
async def get_security_score(org_identifier: str, session: SessionDep) -> SecurityScoreOut:
    org = await _resolve_org(session, org_identifier)

    stmt = (
        select(Vulnerability.severity, Vulnerability.status, func.count(Vulnerability.id))
        .where(Vulnerability.organization_id == org.id)
        .group_by(Vulnerability.severity, Vulnerability.status)
    )
    rows = (await session.execute(stmt)).all()

    open_by_sev: dict[Severity, int] = {s: 0 for s in Severity}
    fixed = 0
    false_pos = 0
    for sev, st, count in rows:
        if st == FindingStatus.OPEN or st == FindingStatus.IN_PROGRESS:
            open_by_sev[sev] = open_by_sev.get(sev, 0) + count
        elif st == FindingStatus.FIXED:
            fixed += count
        elif st == FindingStatus.FALSE_POSITIVE:
            false_pos += count

    return SecurityScoreOut(
        organization_id=org.id,
        security_score=compute_score(open_by_sev),
        open_critical=open_by_sev[Severity.CRITICAL],
        open_high=open_by_sev[Severity.HIGH],
        open_medium=open_by_sev[Severity.MEDIUM],
        open_low=open_by_sev[Severity.LOW],
        open_info=open_by_sev[Severity.INFO],
        fixed_total=fixed,
        false_positive_total=false_pos,
    )


@router.get(
    "/organizations/{org_identifier}/vulnerabilities",
    response_model=list[VulnerabilityOut],
)
async def list_vulnerabilities(
    org_identifier: str,
    session: SessionDep,
    severity: Severity | None = None,
    status_: Annotated[FindingStatus | None, Query(alias="status")] = None,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[VulnerabilityOut]:
    org = await _resolve_org(session, org_identifier)

    stmt = select(Vulnerability).where(Vulnerability.organization_id == org.id)
    if severity is not None:
        stmt = stmt.where(Vulnerability.severity == severity)
    if status_ is not None:
        stmt = stmt.where(Vulnerability.status == status_)
    stmt = stmt.order_by(Vulnerability.cvss.desc().nullslast()).limit(limit)

    result = (await session.execute(stmt)).scalars().all()
    return [VulnerabilityOut.model_validate(v) for v in result]


@router.post("/scans", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
async def create_scan(payload: ScanCreate, session: SessionDep) -> ScanOut:
    # Validate org + asset to give a useful 404 instead of a foreign-key error.
    org = await _resolve_org(session, payload.organization_id)
    asset = (
        await session.execute(
            select(Asset)
            .where(Asset.id == payload.asset_id, Asset.organization_id == org.id)
        )
    ).scalar_one_or_none()
    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"asset {payload.asset_id!r} not found in organization {org.id!r}",
        )

    scan = Scan(
        organization_id=org.id,
        asset_id=asset.id,
        scan_type=payload.scan_type,
        status=ScanStatus.QUEUED,
        config=payload.config,
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)
    return ScanOut.model_validate(scan)


@router.get("/scans/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: str, session: SessionDep) -> ScanOut:
    scan = await session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"scan {scan_id!r} not found"
        )
    return ScanOut.model_validate(scan)

"""Seed the dev database with the same demo data the static dashboard ships with.

Run with::

    python -m asms_api.seed

It will (re)create the schema and insert one tenant (`acme`), a handful of
assets, one completed scan, and 12 vulnerabilities matching
``asms/dashboard/data/sample.json``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import delete

from asms_api.db import SessionLocal, init_models
from asms_api.models import (
    Asset,
    FindingStatus,
    Organization,
    Scan,
    ScanStatus,
    Severity,
    Vulnerability,
)

SAMPLE_JSON = (
    Path(__file__).resolve().parent.parent.parent / "dashboard" / "data" / "sample.json"
)


def _fingerprint(asset_id: str, finding_type: str, url: str | None, parameter: str | None) -> str:
    blob = "|".join([asset_id, finding_type, url or "", parameter or ""])
    return hashlib.sha256(blob.encode()).hexdigest()


async def seed() -> None:
    await init_models()

    if not SAMPLE_JSON.exists():
        raise RuntimeError(
            f"sample dashboard data not found at {SAMPLE_JSON}; nothing to seed"
        )
    sample = json.loads(SAMPLE_JSON.read_text())

    async with SessionLocal() as session:
        # Wipe (in FK-friendly order) so seeding is idempotent during dev.
        await session.execute(delete(Vulnerability))
        await session.execute(delete(Scan))
        await session.execute(delete(Asset))
        await session.execute(delete(Organization))

        org = Organization(
            id="00000000-0000-0000-0000-000000000001",
            name=sample["organization"]["name"],
            slug="acme",
        )
        session.add(org)

        # Build a single primary web asset and reuse it for every finding.
        primary_asset = Asset(
            id="00000000-0000-0000-0000-000000000010",
            organization_id=org.id,
            asset_type="web",
            value="https://www.acme.com",
            criticality=5,
        )
        session.add(primary_asset)

        scan = Scan(
            id="00000000-0000-0000-0000-000000000100",
            organization_id=org.id,
            asset_id=primary_asset.id,
            scan_type="dast",
            status=ScanStatus.COMPLETED,
            config={"checks": ["dast.headers", "dast.tls"]},
            created_at=datetime.now(timezone.utc) - timedelta(hours=4),
            started_at=datetime.now(timezone.utc) - timedelta(hours=4),
            finished_at=datetime.now(timezone.utc) - timedelta(hours=3),
        )
        session.add(scan)

        for raw in sample["vulnerabilities"]:
            sev = Severity(raw["severity"])
            st = FindingStatus(raw["status"])
            url = raw.get("url")
            parameter = raw.get("parameter")
            vuln = Vulnerability(
                id=raw["id"],
                organization_id=org.id,
                asset_id=primary_asset.id,
                scan_id=scan.id,
                type=raw["type"],
                severity=sev,
                cvss=raw.get("cvss"),
                title=raw["title"],
                description=raw.get("description") or raw["title"],
                url=url,
                parameter=parameter,
                status=st,
                fingerprint=_fingerprint(primary_asset.id, raw["type"], url, parameter),
            )
            session.add(vuln)

        await session.commit()
        print(
            f"seeded {len(sample['vulnerabilities'])} vulnerabilities for org {org.slug!r}"
        )


if __name__ == "__main__":
    asyncio.run(seed())

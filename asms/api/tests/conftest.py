"""Test config: spin a fresh in-memory SQLite per test session."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

os.environ.setdefault("ASMS_DATABASE_URL", "sqlite+aiosqlite:///./asms-test.db")


@pytest_asyncio.fixture
async def client() -> AsyncIterator[AsyncClient]:
    # Re-import lazily so the env var above takes effect before engine creation.
    from asms_api.db import engine, init_models
    from asms_api.main import app
    from asms_api.models import Base

    # Fresh schema for each test.
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await init_models()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

    # Drop schema so the next test starts clean. Connections are recycled
    # by SQLAlchemy's pool automatically.
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
def seed_org_id() -> str:
    return "11111111-1111-1111-1111-111111111111"


@pytest.fixture
def seed_asset_id() -> str:
    return "22222222-2222-2222-2222-222222222222"


@pytest_asyncio.fixture
async def seeded(client: AsyncClient, seed_org_id: str, seed_asset_id: str):
    from asms_api.db import SessionLocal
    from asms_api.models import (
        Asset,
        FindingStatus,
        Organization,
        Severity,
        Vulnerability,
    )

    async with SessionLocal() as session:
        org = Organization(id=seed_org_id, name="Acme", slug="acme")
        session.add(org)
        session.add(
            Asset(
                id=seed_asset_id,
                organization_id=seed_org_id,
                asset_type="web",
                value="https://acme.example",
            )
        )

        # 1 critical + 2 high + 1 medium + 1 fixed-high (excluded from score)
        for i, (sev, st, cvss) in enumerate(
            [
                (Severity.CRITICAL, FindingStatus.OPEN, 9.8),
                (Severity.HIGH, FindingStatus.OPEN, 8.2),
                (Severity.HIGH, FindingStatus.IN_PROGRESS, 7.5),
                (Severity.MEDIUM, FindingStatus.OPEN, 5.1),
                (Severity.HIGH, FindingStatus.FIXED, 7.0),
            ]
        ):
            session.add(
                Vulnerability(
                    organization_id=seed_org_id,
                    asset_id=seed_asset_id,
                    type=f"type-{i}",
                    severity=sev,
                    status=st,
                    cvss=cvss,
                    title=f"Finding {i}",
                    description="…",
                    fingerprint=f"fp-{i}",
                )
            )
        await session.commit()

    return {"org_id": seed_org_id, "asset_id": seed_asset_id}

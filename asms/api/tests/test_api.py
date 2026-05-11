"""End-to-end API tests against the FastAPI app."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_endpoint(client: AsyncClient) -> None:
    r = await client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_security_score_uses_open_findings_only(
    client: AsyncClient, seeded
) -> None:
    # open: 1 critical + 1 high + 1 in_progress-high + 1 medium = 20 + 8 + 8 + 3 = 39
    # score = 100 - 39 = 61
    r = await client.get(f"/api/v1/organizations/{seeded['org_id']}/security-score")
    assert r.status_code == 200
    data = r.json()
    assert data["security_score"] == 61
    assert data["open_critical"] == 1
    assert data["open_high"] == 2  # open + in_progress are both "open-ish"
    assert data["open_medium"] == 1
    assert data["fixed_total"] == 1


@pytest.mark.asyncio
async def test_security_score_by_slug(client: AsyncClient, seeded) -> None:
    r = await client.get("/api/v1/organizations/acme/security-score")
    assert r.status_code == 200
    assert r.json()["security_score"] == 61


@pytest.mark.asyncio
async def test_security_score_unknown_org_404(client: AsyncClient) -> None:
    r = await client.get("/api/v1/organizations/does-not-exist/security-score")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_list_vulnerabilities_filters_by_severity(
    client: AsyncClient, seeded
) -> None:
    r = await client.get(
        f"/api/v1/organizations/{seeded['org_id']}/vulnerabilities",
        params={"severity": "high"},
    )
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 3  # two open high + one fixed high
    assert {row["severity"] for row in rows} == {"high"}


@pytest.mark.asyncio
async def test_list_vulnerabilities_filters_by_status(
    client: AsyncClient, seeded
) -> None:
    r = await client.get(
        f"/api/v1/organizations/{seeded['org_id']}/vulnerabilities",
        params={"status": "fixed"},
    )
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 1
    assert rows[0]["status"] == "fixed"


@pytest.mark.asyncio
async def test_list_vulnerabilities_sorted_by_cvss_desc(
    client: AsyncClient, seeded
) -> None:
    r = await client.get(
        f"/api/v1/organizations/{seeded['org_id']}/vulnerabilities"
    )
    cvss_values = [row["cvss"] for row in r.json()]
    assert cvss_values == sorted(cvss_values, reverse=True)


@pytest.mark.asyncio
async def test_create_scan_then_get(client: AsyncClient, seeded) -> None:
    r = await client.post(
        "/api/v1/scans",
        json={
            "organization_id": seeded["org_id"],
            "asset_id": seeded["asset_id"],
            "scan_type": "dast",
            "config": {"checks": ["dast.headers"]},
        },
    )
    assert r.status_code == 201, r.text
    scan = r.json()
    assert scan["status"] == "queued"
    assert scan["scan_type"] == "dast"
    assert scan["config"] == {"checks": ["dast.headers"]}

    r2 = await client.get(f"/api/v1/scans/{scan['id']}")
    assert r2.status_code == 200
    assert r2.json()["id"] == scan["id"]


@pytest.mark.asyncio
async def test_create_scan_with_bad_asset_404(client: AsyncClient, seeded) -> None:
    r = await client.post(
        "/api/v1/scans",
        json={
            "organization_id": seeded["org_id"],
            "asset_id": "33333333-3333-3333-3333-333333333333",
            "scan_type": "dast",
        },
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_create_scan_rejects_unknown_scan_type(
    client: AsyncClient, seeded
) -> None:
    r = await client.post(
        "/api/v1/scans",
        json={
            "organization_id": seeded["org_id"],
            "asset_id": seeded["asset_id"],
            "scan_type": "totally-made-up",
        },
    )
    assert r.status_code == 422  # Pydantic validation error


@pytest.mark.asyncio
async def test_get_missing_scan_404(client: AsyncClient) -> None:
    r = await client.get("/api/v1/scans/00000000-0000-0000-0000-000000000999")
    assert r.status_code == 404

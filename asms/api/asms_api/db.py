"""Database engine + session factory.

Uses async SQLAlchemy 2.0 with aiosqlite by default. Override via the
``ASMS_DATABASE_URL`` env var to point at Postgres (``postgresql+asyncpg://…``).
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from asms_api.models import Base

DATABASE_URL = os.environ.get("ASMS_DATABASE_URL", "sqlite+aiosqlite:///./asms.db")

engine = create_async_engine(DATABASE_URL, future=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def init_models() -> None:
    """Create tables if they don't exist. Safe to call on every startup."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_session() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        yield session

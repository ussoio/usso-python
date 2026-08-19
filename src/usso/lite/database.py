"""Async SQLAlchemy engine and session management for USSO Lite."""

from __future__ import annotations

import asyncio
import os
import stat
from collections.abc import AsyncIterator

from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .base import Base

__all__ = [
    "LiteDatabase",
    "configure",
    "dispose",
    "ensure_initialized",
    "get_session",
    "init_db",
]


class LiteDatabase:
    """Isolated database runtime for one Lite router/application."""

    def __init__(self, database_url: str) -> None:
        """Create an isolated engine and session factory."""
        _secure_sqlite_file(database_url)
        self.engine = create_async_engine(database_url)
        self.session_maker = async_sessionmaker(
            self.engine, expire_on_commit=False
        )
        self.initialized = False
        self._init_lock = asyncio.Lock()

    async def init_db(self) -> None:
        """Create all Lite tables once, safely under concurrent requests."""
        if self.initialized:
            return
        async with self._init_lock:
            if self.initialized:
                return
            from . import (  # ruff: ignore[unused-import]
                models as _models,
            )

            async with self.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            self.initialized = True

    async def ensure_initialized(self) -> None:
        """FastAPI dependency that initializes this runtime lazily."""
        await self.init_db()

    async def dispose(self) -> None:
        """Close pooled connections and background SQLite worker threads."""
        await self.engine.dispose()
        self.initialized = False

    async def get_session(self) -> AsyncIterator[AsyncSession]:
        """Yield a session owned by this runtime."""
        session = self.session_maker()
        try:
            yield session
        finally:
            await session.close()


def _secure_sqlite_file(database_url: str) -> None:
    """Pre-create a file-backed SQLite database with private permissions."""
    url = make_url(database_url)
    if url.get_backend_name() != "sqlite" or not url.database:
        return
    if url.database == ":memory:" or url.database.startswith("file:"):
        return
    path = os.path.abspath(url.database)
    if os.path.lexists(path):
        mode = os.lstat(path).st_mode
        if not stat.S_ISREG(mode):
            raise RuntimeError("USSO Lite database must be a regular file.")
        os.chmod(path, 0o600)
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)


_engine: AsyncEngine | None = None
_session_maker: async_sessionmaker[AsyncSession] | None = None
_initialized = False


def configure(database_url: str) -> None:
    """
    Configure the global async engine for the given SQLAlchemy URL.

    Must be called before ``get_session`` is used. Calling it again
    replaces the engine.
    """
    global _engine, _session_maker, _initialized
    _engine = create_async_engine(database_url)
    _session_maker = async_sessionmaker(_engine, expire_on_commit=False)
    _initialized = False


async def init_db() -> None:
    """Create all database tables (idempotent)."""
    global _initialized
    if _engine is None:
        raise RuntimeError(
            "Database is not configured. Call configure() or "
            "create_lite_router() first."
        )
    from . import (
        models as _models,  # ruff: ignore[unused-import]  # register models with Base
    )

    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    _initialized = True


async def ensure_initialized() -> None:
    """Ensure tables exist before the first request is handled."""
    if not _initialized:
        await init_db()


async def dispose() -> None:
    """Close the global engine and release its SQLite worker threads."""
    global _engine, _session_maker, _initialized
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_maker = None
        _initialized = False


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding an async database session."""
    if _session_maker is None:
        raise RuntimeError(
            "Database is not configured. Call configure() or "
            "create_lite_router() first."
        )
    session = _session_maker()
    try:
        yield session
    finally:
        await session.close()

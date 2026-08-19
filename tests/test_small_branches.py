"""Coverage tests for small remaining branches across modules."""

import json
from datetime import datetime

import pytest
from sqlalchemy import select

from src.usso.config import AuthConfig
from src.usso.enums import AuthIdentifier, AuthSecret
from src.usso.lite import LiteAuth, LiteConfig, dependency
from src.usso.lite.database import (
    configure,
    dispose,
    ensure_initialized,
    get_session,
    init_db,
)
from src.usso.lite.models import LocalSession
from src.usso.lite.schemas import Identifier, LoginRequest, RegisterRequest


@pytest.fixture
async def lite_setup() -> tuple[LiteConfig, LiteAuth]:
    """Create a fresh in-memory LiteAuth instance and configure the DB."""
    await dispose()
    cfg = LiteConfig(
        database_url="sqlite+aiosqlite:///:memory:",
        expose_otp_in_response=True,
    )
    auth = LiteAuth(cfg)
    configure(cfg.database_url)
    await init_db()
    return cfg, auth


# ---------------------------------------------------------------------------
# config.py
# ---------------------------------------------------------------------------
def test_auth_config_get_jwt_without_header() -> None:
    """get_jwt returns None when no JWT header is configured."""
    config = AuthConfig(key={"kty": "oct", "k": "c2VjcmV0"}, jwt_header=None)
    assert config.get_jwt(object()) is None


def test_auth_config_parse_from_json_string() -> None:
    """_parse_config accepts a JSON string."""
    config = AuthConfig._parse_config(
        json.dumps({"jwks_url": "https://sso/jwks.json"})
    )
    assert config.jwks_url == "https://sso/jwks.json"


# ---------------------------------------------------------------------------
# lite/schemas.py
# ---------------------------------------------------------------------------
def test_lite_identifier_infers_type() -> None:
    """Identifier infers the identifier type when none is given."""
    from src.usso.lite.schemas import Identifier as LiteIdentifier

    ident = LiteIdentifier(identifier="a@b.com")
    assert ident.type == AuthIdentifier.EMAIL


def test_lite_register_requires_password() -> None:
    """RegisterRequest rejects missing or short passwords."""
    with pytest.raises(ValueError):
        RegisterRequest(
            type=AuthIdentifier.EMAIL,
            identifier="a@b.com",
            method=AuthSecret.PASSWORD,
            secret=None,
        )
    with pytest.raises(ValueError):
        RegisterRequest(
            type=AuthIdentifier.EMAIL,
            identifier="a@b.com",
            method=AuthSecret.PASSWORD,
            secret="short",
        )


# ---------------------------------------------------------------------------
# lite/models.py
# ---------------------------------------------------------------------------
def test_session_expire_at_none() -> None:
    """LocalSession without a max age never expires."""
    session = LocalSession()
    session.max_age_minutes = None
    assert session.expire_at is None
    assert session.is_expired is False


# ---------------------------------------------------------------------------
# lite/base.py
# ---------------------------------------------------------------------------
def test_entity_dump_branches() -> None:
    """BaseEntity.dump honours include, exclude and datetime values."""
    from src.usso.lite.base import BaseEntity

    class _Demo(BaseEntity):
        __abstract__ = True
        _hidden: str
        dt: datetime

    entity = _Demo()
    entity.uid = "u1"
    entity._hidden = "secret"
    entity.dt = datetime(2024, 1, 1, 12, 0, 0)

    dumped = entity.dump(include_fields=["uid", "dt"], exclude_fields=["uid"])
    assert dumped == {"dt": "2024-01-01T12:00:00"}

    full = entity.dump()
    assert "_hidden" not in full


# ---------------------------------------------------------------------------
# lite/database.py
# ---------------------------------------------------------------------------
async def test_init_db_twice_is_idempotent() -> None:
    """Calling init_db twice only creates tables once."""
    await dispose()
    cfg = LiteConfig(database_url="sqlite+aiosqlite:///:memory:")
    LiteAuth(cfg)
    configure(cfg.database_url)
    await init_db()
    await init_db()
    await dispose()


async def test_global_ensure_initialized_and_dispose() -> None:
    """Global ensure_initialized and dispose work end to end."""
    await dispose()
    cfg = LiteConfig(database_url="sqlite+aiosqlite:///:memory:")
    LiteAuth(cfg)
    configure(cfg.database_url)
    await ensure_initialized()
    async for session in get_session():
        await session.execute(select(LocalSession))
    await dispose()


async def test_init_db_unconfigured_raises() -> None:
    """Global init_db raises when no engine is configured."""
    await dispose()
    with pytest.raises(RuntimeError):
        await init_db()


async def test_get_session_unconfigured_raises() -> None:
    """Global get_session raises when no session maker is configured."""
    await dispose()
    with pytest.raises(RuntimeError):
        async for _ in get_session():
            pass


# ---------------------------------------------------------------------------
# lite/dependency.py
# ---------------------------------------------------------------------------
def test_set_auth_and_get_auth() -> None:
    """_set_auth stores an instance that get_auth returns."""
    saved = dependency._auth
    try:
        auth = LiteAuth(
            LiteConfig(database_url="sqlite+aiosqlite:///:memory:")
        )
        dependency._set_auth(auth)
        assert dependency.get_auth() is auth
    finally:
        dependency._auth = saved


async def test_get_current_user(lite_setup: tuple) -> None:
    """get_current_user resolves the user via the configured auth."""
    from starlette.requests import Request

    _cfg, auth = lite_setup
    saved = dependency._auth
    try:
        dependency._set_auth(auth)
        async for session in get_session():
            await auth.create_user(
                identifier=Identifier(
                    type=AuthIdentifier.EMAIL, identifier="ali@example.com"
                ),
                password="super-secret-1",
                session=session,
            )
            pair, _ = await auth.login(
                LoginRequest(
                    type=AuthIdentifier.EMAIL,
                    identifier="ali@example.com",
                    method=AuthSecret.PASSWORD,
                    secret="super-secret-1",
                ),
                session,
            )
            scope: dict[str, object] = {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": "GET",
                "scheme": "http",
                "path": "/",
                "raw_path": b"/",
                "query_string": b"",
                "headers": [
                    (b"authorization", f"Bearer {pair.access_token}".encode())
                ],
                "client": ("127.0.0.1", 50000),
                "server": ("testserver", 80),
            }
            request = Request(scope)
            user = await dependency.get_current_user(request, session)
            assert user is not None
    finally:
        dependency._auth = saved

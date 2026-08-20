"""Coverage tests for USSO Lite dependency resolution."""

import pytest
from sqlalchemy import delete as _delete
from starlette.requests import Request

from usso.enums import AuthIdentifier, AuthSecret
from usso.exceptions import USSOException
from usso.lite import LiteAuth, LiteConfig, dependency
from usso.lite.database import configure, dispose, get_session, init_db
from usso.lite.models import LocalSession
from usso.lite.schemas import Identifier, LoginRequest


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


def _bearer_request(token: str) -> Request:
    """Build a request carrying a bearer token."""
    scope: dict[str, object] = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [(b"authorization", f"Bearer {token}".encode())],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }
    return Request(scope)


async def test_resolve_current_user_inactive(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """resolve_current_user rejects a deactivated user."""
    _cfg, auth = lite_setup
    async for session in get_session():
        user = await auth.create_user(
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
        user.is_active = False
        await session.commit()
        with pytest.raises(USSOException) as exc_info:
            await dependency.resolve_current_user(
                _bearer_request(pair.access_token), session, auth
            )
        assert exc_info.value.status_code == 401


async def test_resolve_current_user_missing_session(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """resolve_current_user rejects a token whose session is gone."""
    _cfg, auth = lite_setup
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
        await session.execute(_delete(LocalSession))
        await session.commit()
        with pytest.raises(USSOException) as exc_info:
            await dependency.resolve_current_user(
                _bearer_request(pair.access_token), session, auth
            )
        assert exc_info.value.status_code == 401


async def test_resolve_current_user_ok(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """resolve_current_user returns the user for a valid token."""
    _cfg, auth = lite_setup
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
        user = await dependency.resolve_current_user(
            _bearer_request(pair.access_token), session, auth
        )
        assert user is not None

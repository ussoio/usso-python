"""Direct-call coverage tests for the USSO Lite router flow functions."""

import pytest
from starlette.requests import Request

from usso.enums import AuthIdentifier, AuthSecret
from usso.exceptions import USSOException
from usso.lite import LiteAuth, LiteConfig
from usso.lite import router as router_mod
from usso.lite.database import configure, dispose, get_session, init_db
from usso.lite.schemas import (
    ChangePasswordRequest,
    Identifier,
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    RequestOTPRequest,
    UserCreateRequest,
    UserUpdateRequest,
)


@pytest.fixture
async def lite_setup() -> tuple[LiteConfig, LiteAuth]:
    """Create a fresh in-memory LiteAuth instance and configure the DB."""
    await dispose()
    cfg = LiteConfig(
        database_url="sqlite+aiosqlite:///:memory:",
        expose_otp_in_response=True,
        default_scopes=["admin:usso/lite/users"],
    )
    auth = LiteAuth(cfg)
    configure(cfg.database_url)
    await init_db()
    return cfg, auth


def _request() -> Request:
    """Build a minimal Starlette Request."""
    scope: dict[str, object] = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [(b"user-agent", b"pytest")],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }
    return Request(scope)


async def test_jwks_flow(lite_setup: tuple[LiteConfig, LiteAuth]) -> None:
    """_jwks_flow exposes the public signing key."""
    _cfg, auth = lite_setup
    result = await router_mod._jwks_flow(auth)
    assert "keys" in result
    assert result["keys"][0]["kty"] == "OKP"


async def test_register_flow(lite_setup: tuple[LiteConfig, LiteAuth]) -> None:
    """_register_flow registers and logs in a user."""
    cfg, auth = lite_setup
    async for session in get_session():
        payload = RegisterRequest(
            type=AuthIdentifier.EMAIL,
            identifier="ali@example.com",
            method=AuthSecret.PASSWORD,
            secret="super-secret-1",
            name="Ali",
        )
        response = await router_mod._register_flow(
            cfg, auth, payload, _request(), session
        )
        assert response.access_token
        assert response.name == "Ali"


async def test_register_flow_disabled() -> None:
    """_register_flow rejects registration when disabled."""
    await dispose()
    cfg = LiteConfig(
        database_url="sqlite+aiosqlite:///:memory:",
        allow_registration=False,
    )
    auth = LiteAuth(cfg)
    configure(cfg.database_url)
    await init_db()
    async for session in get_session():
        payload = RegisterRequest(
            type=AuthIdentifier.EMAIL,
            identifier="ali@example.com",
            method=AuthSecret.PASSWORD,
            secret="super-secret-1",
        )
        with pytest.raises(USSOException) as exc_info:
            await router_mod._register_flow(
                cfg, auth, payload, _request(), session
            )
        assert exc_info.value.status_code == 403


async def test_login_flow(lite_setup: tuple[LiteConfig, LiteAuth]) -> None:
    """_login_flow authenticates a user and returns tokens."""
    _cfg, auth = lite_setup
    async for session in get_session():
        await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password="super-secret-1",
            session=session,
        )
        payload = LoginRequest(
            type=AuthIdentifier.EMAIL,
            identifier="ali@example.com",
            method=AuthSecret.PASSWORD,
            secret="super-secret-1",
        )
        response = await router_mod._login_flow(
            auth, payload, _request(), session
        )
        assert response.access_token


async def test_refresh_flow(lite_setup: tuple[LiteConfig, LiteAuth]) -> None:
    """_refresh_flow rotates tokens for a session."""
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
        refreshed = await router_mod._refresh_flow(
            auth, RefreshRequest(refresh_token=pair.refresh_token), session
        )
        assert refreshed.access_token


async def test_logout_flow(lite_setup: tuple[LiteConfig, LiteAuth]) -> None:
    """_logout_flow ends the session."""
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
        await router_mod._logout_flow(
            auth, RefreshRequest(refresh_token=pair.refresh_token), session
        )


async def test_request_otp_flow(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """_request_otp_flow returns an OTP code when exposed."""
    cfg, auth = lite_setup
    async for session in get_session():
        result = await router_mod._request_otp_flow(
            cfg,
            auth,
            RequestOTPRequest(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            _request(),
            session,
        )
        assert "code" in result


async def test_change_password_flow(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """_change_password_flow changes the current password."""
    _cfg, auth = lite_setup
    async for session in get_session():
        user = await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password="super-secret-1",
            session=session,
        )
        await router_mod._change_password_flow(
            auth,
            user,
            ChangePasswordRequest(
                old_password="super-secret-1",
                new_password="brand-new-pass-1",
            ),
            session,
        )


async def test_me_flow(lite_setup: tuple[LiteConfig, LiteAuth]) -> None:
    """_me_flow returns the current user profile."""
    _cfg, auth = lite_setup
    async for session in get_session():
        user = await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password="super-secret-1",
            session=session,
            name="Ali",
        )
        response = await router_mod._me_flow(auth, user, session)
        assert response.name == "Ali"


async def test_list_users_flow(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """_list_users_flow returns paginated users."""
    _cfg, auth = lite_setup
    async for session in get_session():
        for i in range(3):
            await auth.create_user(
                identifier=Identifier(
                    type=AuthIdentifier.EMAIL,
                    identifier=f"user{i}@example.com",
                ),
                password="super-secret-1",
                session=session,
            )
        result = await router_mod._list_users_flow(
            auth, session, offset=0, limit=2
        )
        assert result["total"] == 3
        assert len(result["items"]) == 2


async def test_create_user_flow(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """_create_user_flow creates a user directly."""
    _cfg, auth = lite_setup
    async for session in get_session():
        response = await router_mod._create_user_flow(
            auth,
            UserCreateRequest(
                type=AuthIdentifier.EMAIL,
                identifier="jane@example.com",
                password="super-secret-1",
                name="Jane",
            ),
            session,
        )
        assert response.name == "Jane"


async def test_get_user_flow(lite_setup: tuple[LiteConfig, LiteAuth]) -> None:
    """_get_user_flow returns a user by uid and raises for missing users."""
    _cfg, auth = lite_setup
    async for session in get_session():
        user = await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password="super-secret-1",
            session=session,
        )
        response = await router_mod._get_user_flow(auth, user.uid, session)
        assert response.uid == user.uid
        with pytest.raises(USSOException) as exc_info:
            await router_mod._get_user_flow(auth, "missing", session)
        assert exc_info.value.status_code == 404


async def test_update_user_flow(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """_update_user_flow updates a user and rejects missing users."""
    _cfg, auth = lite_setup
    async for session in get_session():
        user = await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password="super-secret-1",
            session=session,
            name="Ali",
        )
        response = await router_mod._update_user_flow(
            auth,
            user.uid,
            UserUpdateRequest(name="Ali Reza"),
            session,
        )
        assert response.name == "Ali Reza"
        with pytest.raises(USSOException):
            await router_mod._update_user_flow(
                auth, "missing", UserUpdateRequest(name="X"), session
            )


async def test_delete_user_flow(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """_delete_user_flow soft-deletes a user and rejects missing users."""
    _cfg, auth = lite_setup
    async for session in get_session():
        user = await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password="super-secret-1",
            session=session,
        )
        await router_mod._delete_user_flow(auth, user.uid, session)
        with pytest.raises(USSOException):
            await router_mod._delete_user_flow(auth, "missing", session)

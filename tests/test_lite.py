"""Tests for the USSO Lite module."""

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from usso.enums import AuthIdentifier, AuthSecret
from usso.exceptions import USSOException
from usso.lite import (
    EXCEPTION_HANDLERS,
    LiteAuth,
    LiteConfig,
    create_lite_router,
)
from usso.lite.database import configure, get_session, init_db
from usso.lite.schemas import Identifier, LoginRequest


@pytest.fixture
async def lite_setup() -> tuple[LiteConfig, LiteAuth]:
    """Create a fresh in-memory LiteAuth instance and configure the DB."""
    from usso.lite.database import dispose

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


def _email_login(
    identifier: str, secret: str, method: AuthSecret = AuthSecret.PASSWORD
) -> LoginRequest:
    """Build an email login request."""
    return LoginRequest(
        type=AuthIdentifier.EMAIL,
        identifier=identifier,
        method=method,
        secret=secret,
    )


async def test_register_and_login(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Register a user and authenticate with a valid password."""
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
        assert user.name == "Ali"

        pair, logged = await auth.login(
            _email_login("ali@example.com", "super-secret-1"), session
        )
        assert logged.uid == user.uid
        assert pair.access_token and pair.refresh_token
        assert pair.expires_in > 0

        payload = auth.verify_token(pair.access_token)
        assert payload.uid == user.uid
        assert payload.email == "ali@example.com"
        assert payload.user_name == "Ali"
        assert payload.session_id
        assert payload.acr == "usso:acr:1"


async def test_login_rejects_wrong_password(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Reject login with an incorrect password."""
    _cfg, auth = lite_setup
    async for session in get_session():
        await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password="super-secret-1",
            session=session,
        )
        with pytest.raises(USSOException) as exc_info:
            await auth.login(_email_login("ali@example.com", "wrong"), session)
        assert exc_info.value.status_code == 401


async def test_duplicate_identifier_rejected(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Reject creating a second user with the same identifier."""
    _cfg, auth = lite_setup
    async for session in get_session():
        await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password="super-secret-1",
            session=session,
        )
        with pytest.raises(USSOException) as exc_info:
            await auth.create_user(
                identifier=Identifier(
                    type=AuthIdentifier.EMAIL, identifier="ali@example.com"
                ),
                password="another-pass-1",
                session=session,
            )
        assert exc_info.value.status_code == 409


async def test_refresh_rotates_tokens(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Refreshing issues a brand new access and refresh token."""
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
            _email_login("ali@example.com", "super-secret-1"), session
        )
        refreshed = await auth.refresh(pair.refresh_token, session)
        assert refreshed.access_token != pair.access_token
        assert refreshed.refresh_token != pair.refresh_token


async def test_logout_invalidates_session(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Logout invalidates the session so refresh is rejected."""
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
            _email_login("ali@example.com", "super-secret-1"), session
        )
        await auth.logout(pair.refresh_token, session)
        with pytest.raises(USSOException) as exc_info:
            await auth.refresh(pair.refresh_token, session)
        assert exc_info.value.status_code == 401


async def test_change_password(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Changing a password invalidates the old one."""
    _cfg, auth = lite_setup
    async for session in get_session():
        user = await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password="super-secret-1",
            session=session,
        )
        await auth.change_password(
            user,
            old_password="super-secret-1",
            new_password="brand-new-pass-1",
            session=session,
        )
        with pytest.raises(USSOException):
            await auth.login(
                _email_login("ali@example.com", "super-secret-1"), session
            )
        await auth.login(
            _email_login("ali@example.com", "brand-new-pass-1"), session
        )


async def test_otp_request_and_verify(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """OTP codes are delivered, valid once, and single use."""
    cfg, auth = lite_setup
    delivered: dict[str, str] = {}

    async def sender(  # callback is awaited by LiteAuth
        identifier_type: str, identifier: str, code: str
    ) -> None:
        delivered[identifier] = code

    cfg.otp_sender = sender
    async for session in get_session():
        code = await auth.request_otp(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="new@example.com"
            ),
            session=session,
        )
        assert delivered["new@example.com"] == code
        assert len(code) == cfg.otp_length

        assert await auth.verify_otp(
            identifier_type=AuthIdentifier.EMAIL,
            identifier="new@example.com",
            code=code,
            purpose="login",
            session=session,
        )
        # Codes are single use.
        assert not await auth.verify_otp(
            identifier_type=AuthIdentifier.EMAIL,
            identifier="new@example.com",
            code=code,
            purpose="login",
            session=session,
        )


async def test_otp_wrong_code_increments_attempts(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Exceeding the attempt limit invalidates the OTP code."""
    cfg, auth = lite_setup
    async for session in get_session():
        code = await auth.request_otp(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="new@example.com"
            ),
            session=session,
        )
        for _ in range(cfg.otp_max_attempts):
            assert not await auth.verify_otp(
                identifier_type=AuthIdentifier.EMAIL,
                identifier="new@example.com",
                code="000000",
                purpose="login",
                session=session,
            )
        # Correct code now fails after exceeding max attempts.
        assert not await auth.verify_otp(
            identifier_type=AuthIdentifier.EMAIL,
            identifier="new@example.com",
            code=code,
            purpose="login",
            session=session,
        )


async def test_login_with_otp(lite_setup: tuple[LiteConfig, LiteAuth]) -> None:
    """A user can log in with an OTP code instead of a password."""
    _cfg, auth = lite_setup
    async for session in get_session():
        await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password="super-secret-1",
            session=session,
        )
        code = await auth.request_otp(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            session=session,
        )
        pair, user = await auth.login(
            _email_login("ali@example.com", code, AuthSecret.EMAIL_OTP),
            session,
        )
        assert pair.access_token
        assert user is not None
        assert auth.verify_token(pair.access_token).acr == "usso:acr:1"


async def test_user_response_shape(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """The public user response exposes identifiers and credential methods."""
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
        resp = await auth.to_user_response(user, session)
        assert resp.uid == user.uid
        assert resp.identifiers == ["email:ali@example.com"]
        assert resp.credential_methods == ["password"]


@pytest.fixture
def client() -> TestClient:
    """Mount the USSO Lite router on an in-memory DB and return a client."""
    app = FastAPI()
    for exc, handler in EXCEPTION_HANDLERS.items():
        app.add_exception_handler(exc, handler)
    cfg = LiteConfig(
        database_url="sqlite+aiosqlite:///:memory:",
        expose_otp_in_response=True,
        default_scopes=["admin:usso/lite/users"],
    )
    app.include_router(create_lite_router(cfg))
    return TestClient(app)


def test_router_register_login_flow(client: TestClient) -> None:
    """Exercise register, login, me, refresh and logout via the API."""
    r = client.post(
        "/auth/register",
        json={
            "type": "email",
            "identifier": "ali@example.com",
            "method": "password",
            "secret": "super-secret-1",
            "name": "Ali",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "Ali"
    assert body["access_token"]

    access = body["access_token"]
    refresh = body["refresh_token"]

    r = client.post(
        "/auth/login",
        json={
            "type": "email",
            "identifier": "ali@example.com",
            "method": "password",
            "secret": "super-secret-1",
        },
    )
    assert r.status_code == 200
    access = r.json()["access_token"]

    r = client.get("/users/me", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 200
    assert r.json()["name"] == "Ali"

    r = client.get("/users/me")
    assert r.status_code == 401

    r = client.post("/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 200
    rotated_refresh = r.json()["refresh_token"]
    rotated_access = r.json()["access_token"]

    client.cookies.set("usso-refresh-token", rotated_refresh)
    r = client.get("/auth/refresh")
    assert r.status_code == 200
    cookie_rotated_refresh = r.json()["refresh_token"]
    client.cookies.set("usso-refresh-token", cookie_rotated_refresh)

    # Rotation makes the previous refresh token unusable.
    r = client.post("/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 401

    r = client.post("/auth/refresh")
    assert r.status_code == 200
    rotated_refresh = r.json()["refresh_token"]

    r = client.post("/auth/logout", json={"refresh_token": rotated_refresh})
    assert r.status_code == 204

    r = client.post("/auth/refresh", json={"refresh_token": rotated_refresh})
    assert r.status_code == 401
    r = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {rotated_access}"},
    )
    assert r.status_code == 401


def test_router_otp(client: TestClient) -> None:
    """Exercise OTP request and OTP login via the API."""
    r = client.post(
        "/auth/register",
        json={
            "type": "email",
            "identifier": "ali@example.com",
            "method": "password",
            "secret": "super-secret-1",
        },
    )
    assert r.status_code == 200

    r = client.post(
        "/auth/request-otp",
        json={"type": "email", "identifier": "ali@example.com"},
    )
    assert r.status_code == 200
    code = r.json()["code"]

    r = client.post(
        "/auth/login",
        json={
            "type": "email",
            "identifier": "ali@example.com",
            "method": "email/otp",
            "secret": code,
        },
    )
    assert r.status_code == 200
    assert r.json()["access_token"]


def test_router_user_crud(client: TestClient) -> None:
    """Exercise user CRUD endpoints via the API."""
    r = client.post(
        "/auth/register",
        json={
            "type": "email",
            "identifier": "admin@example.com",
            "method": "password",
            "secret": "super-secret-1",
        },
    )
    access = r.json()["access_token"]
    headers = {"Authorization": f"Bearer {access}"}

    r = client.post(
        "/users",
        json={
            "type": "username",
            "identifier": "jane",
            "password": "super-secret-1",
            "name": "Jane",
        },
        headers=headers,
    )
    assert r.status_code == 200
    uid = r.json()["uid"]
    assert r.json()["identifiers"] == ["username:jane"]

    r = client.get(f"/users/{uid}", headers=headers)
    assert r.status_code == 200
    assert r.json()["name"] == "Jane"

    r = client.patch(
        f"/users/{uid}",
        json={"name": "Jane Doe", "is_limited": True},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["name"] == "Jane Doe"
    assert r.json()["is_limited"] is True

    r = client.delete(f"/users/{uid}", headers=headers)
    assert r.status_code == 204

    r = client.get(f"/users/{uid}", headers=headers)
    assert r.status_code == 404


def _new_client(config: LiteConfig) -> TestClient:
    app = FastAPI()
    for exc, handler in EXCEPTION_HANDLERS.items():
        app.add_exception_handler(exc, handler)
    app.include_router(create_lite_router(config))
    return TestClient(app)


def test_secure_defaults_hide_otp_and_protect_admin() -> None:
    """Production defaults neither disclose OTPs nor expose user CRUD."""
    delivered: dict[str, str] = {}

    async def sender(kind: str, identifier: str, code: str) -> None:
        delivered[f"{kind}:{identifier}"] = code

    secure = _new_client(
        LiteConfig(
            database_url="sqlite+aiosqlite:///:memory:",
            otp_sender=sender,
        )
    )
    registered = secure.post(
        "/auth/register",
        json={
            "type": "email",
            "identifier": "user@example.com",
            "method": "password",
            "secret": "super-secret-1",
        },
    )
    assert registered.status_code == 200
    token = registered.json()["access_token"]

    otp = secure.post(
        "/auth/request-otp",
        json={"type": "email", "identifier": "user@example.com"},
    )
    assert otp.status_code == 200
    assert "code" not in otp.json()
    assert delivered["email:user@example.com"]

    users = secure.get("/users", headers={"Authorization": f"Bearer {token}"})
    assert users.status_code == 403


def test_registration_rejects_client_supplied_privileges() -> None:
    """Public registration cannot choose roles or scopes."""
    secure = _new_client(
        LiteConfig(database_url="sqlite+aiosqlite:///:memory:")
    )
    response = secure.post(
        "/auth/register",
        json={
            "type": "email",
            "identifier": "attacker@example.com",
            "method": "password",
            "secret": "super-secret-1",
            "roles": ["admin"],
            "scopes": ["*:*"],
        },
    )
    assert response.status_code == 422


def test_otp_requires_delivery_configuration() -> None:
    """OTP requests fail closed when there is no sender."""
    secure = _new_client(
        LiteConfig(database_url="sqlite+aiosqlite:///:memory:")
    )
    response = secure.post(
        "/auth/request-otp",
        json={"type": "email", "identifier": "user@example.com"},
    )
    assert response.status_code == 503


async def test_inactive_user_cannot_login(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Deactivated accounts cannot receive new sessions."""
    _cfg, auth = lite_setup
    async for session in get_session():
        await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL,
                identifier="inactive@example.com",
            ),
            password="super-secret-1",
            session=session,
            is_active=False,
        )
        with pytest.raises(USSOException) as exc_info:
            await auth.login(
                _email_login("inactive@example.com", "super-secret-1"),
                session,
            )
        assert exc_info.value.error_code == "user_not_active"


def test_signing_key_file_is_private(tmp_path: Path) -> None:
    """Generated signing keys are persisted with owner-only permissions."""
    database = tmp_path / "lite.db"
    LiteAuth(LiteConfig(database_url=f"sqlite+aiosqlite:///{database}"))
    key_path = Path(f"{database}.signing.pem")
    assert key_path.stat().st_mode & 0o777 == 0o600


def test_jwks_exposes_only_public_key(client: TestClient) -> None:
    """JWKS supports standard consumers without leaking private material."""
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    key = response.json()["keys"][0]
    assert key["kty"] == "OKP"
    assert key["crv"] == "Ed25519"
    assert "d" not in key


def test_multiple_lite_apps_are_isolated() -> None:
    """Creating a second router cannot replace the first router runtime."""
    first = _new_client(
        LiteConfig(database_url="sqlite+aiosqlite:///:memory:")
    )
    second = _new_client(
        LiteConfig(database_url="sqlite+aiosqlite:///:memory:")
    )
    payload = {
        "type": "email",
        "identifier": "same@example.com",
        "method": "password",
        "secret": "super-secret-1",
    }
    first_auth = first.post("/auth/register", json=payload)
    second_auth = second.post("/auth/register", json=payload)
    assert first_auth.status_code == 200
    assert second_auth.status_code == 200
    first_me = first.get(
        "/users/me",
        headers={
            "Authorization": f"Bearer {first_auth.json()['access_token']}"
        },
    )
    assert first_me.status_code == 200

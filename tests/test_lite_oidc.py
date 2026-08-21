"""Tests for USSO Lite OIDC identity login (paste/localhost-redirect flow)."""

from __future__ import annotations

import base64
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from usso.enums import AuthIdentifier, AuthSecret
from usso.exceptions import USSOException
from usso.lite import (
    EXCEPTION_HANDLERS,
    LiteAuth,
    LiteConfig,
    OidcProviderConfig,
    create_lite_router,
)
from usso.lite.database import configure, dispose, get_session, init_db
from usso.lite.oidc import (
    OidcStateStore,
    build_oidc_authorization_url,
    parse_oidc_callback,
)
from usso.lite.schemas import Identifier


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _fake_id_token(*, email: str, email_verified: bool = True) -> str:
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64url(
        json.dumps({"email": email, "email_verified": email_verified}).encode()
    )
    return f"{header}.{payload}.sig"


@pytest.fixture
async def lite_oidc_setup() -> tuple[LiteConfig, LiteAuth]:
    """Fresh in-memory LiteAuth with a Google OIDC provider configured."""
    await dispose()
    cfg = LiteConfig(
        database_url="sqlite+aiosqlite:///:memory:",
        oidc_providers={
            "google": OidcProviderConfig(
                client_id="cid",
                client_secret="csecret",
                redirect_uri="http://localhost",
            )
        },
        oidc_allow_signup=False,
        default_scopes=["admin:usso/lite/users"],
    )
    auth = LiteAuth(cfg)
    configure(cfg.database_url)
    await init_db()
    return cfg, auth


# ---------------------------------------------------------------------------
# parse_oidc_callback
# ---------------------------------------------------------------------------


def test_parse_callback_full_url() -> None:
    """Parse a full redirect URL with code and state."""
    parsed = parse_oidc_callback(
        "http://localhost/?code=thecode&state=thest"
    )
    assert parsed.code == "thecode"
    assert parsed.state == "thest"


def test_parse_callback_url_with_hash_query() -> None:
    """Parse OIDC params from a URL fragment."""
    parsed = parse_oidc_callback("http://localhost/#code=fromhash&state=s1")
    assert parsed.code == "fromhash"
    assert parsed.state == "s1"


def test_parse_callback_bare_query_string() -> None:
    """Parse a bare query string paste."""
    parsed = parse_oidc_callback("code=thecode&state=thest")
    assert parsed.code == "thecode"
    assert parsed.state == "thest"


def test_parse_callback_bare_code() -> None:
    """Parse a bare authorization code."""
    parsed = parse_oidc_callback("4/0AeanS-bare-code")
    assert parsed.code == "4/0AeanS-bare-code"
    assert parsed.state is None


def test_parse_callback_rejects_empty() -> None:
    """Reject empty callback paste."""
    with pytest.raises(USSOException) as exc_info:
        parse_oidc_callback("   ")
    assert exc_info.value.error_code == "oidc_callback_invalid"


# ---------------------------------------------------------------------------
# start / authorization URL
# ---------------------------------------------------------------------------


def test_start_builds_url_with_openid_scopes(
    lite_oidc_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """start_oidc builds an authorize URL with openid/email/profile only."""
    _cfg, auth = lite_oidc_setup
    result = auth.start_oidc("google", auth._oidc_states)
    assert result["provider"] == "google"
    assert result["redirect_uri"] == "http://localhost"
    assert result["state"]
    url = result["authorization_url"]
    assert "openid" in url
    assert "email" in url
    assert "profile" in url
    assert "drive" not in url.lower()
    assert "accounts.google.com" in url
    assert "client_id=cid" in url
    assert f"state={result['state']}" in url


def test_build_authorization_url_scopes_only_identity() -> None:
    """build_oidc_authorization_url never includes Drive scopes."""
    cfg = OidcProviderConfig(client_id="c", client_secret="s")
    url = build_oidc_authorization_url(cfg, state="abc")
    assert "scope=openid+email+profile" in url or (
        "openid" in url and "email" in url and "profile" in url
    )
    assert "drive" not in url.lower()


def test_start_unknown_provider(
    lite_oidc_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Unknown OIDC provider names are rejected."""
    _cfg, auth = lite_oidc_setup
    with pytest.raises(USSOException) as exc_info:
        auth.start_oidc("unknown", auth._oidc_states)
    assert exc_info.value.status_code == 404
    assert exc_info.value.error_code == "oidc_provider_not_found"


def test_oidc_state_store_consume_once() -> None:
    """State values are single-use."""
    store = OidcStateStore()
    state = store.create("google")
    assert store.consume(state, provider="google") is True
    assert store.consume(state, provider="google") is False


def test_oidc_state_store_rejects_wrong_provider() -> None:
    """State tied to one provider cannot be consumed for another."""
    store = OidcStateStore()
    state = store.create("google")
    assert store.consume(state, provider="other") is False


# ---------------------------------------------------------------------------
# login_with_oidc
# ---------------------------------------------------------------------------


def _mock_http(
    *,
    access_token: str | None = None,
    id_token: str | None = None,
    userinfo: dict | None = None,
) -> MagicMock:
    """Build a fake httpx.AsyncClient for token + userinfo calls."""
    token_body: dict = {
        "access_token": access_token or "at",
        "token_type": "Bearer",
    }
    if id_token is not None:
        token_body["id_token"] = id_token

    token_resp = MagicMock()
    token_resp.raise_for_status = MagicMock()
    token_resp.json.return_value = token_body
    token_resp.is_success = True
    token_resp.status_code = 200

    info_resp = MagicMock()
    info_resp.raise_for_status = MagicMock()
    info_resp.json.return_value = userinfo or {}
    info_resp.is_success = True
    info_resp.status_code = 200

    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    client.post.return_value = token_resp
    client.get.return_value = info_resp
    return client


async def test_complete_existing_user_login(
    lite_oidc_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Existing LocalUser can complete OIDC login and receive tokens."""
    _cfg, auth = lite_oidc_setup
    async for session in get_session():
        user = await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password="super-secret-1",
            session=session,
            name="Ali",
        )
        started = auth.start_oidc("google", auth._oidc_states)
        client = _mock_http(
            userinfo={
                "email": "ali@example.com",
                "email_verified": True,
                "name": "Ali",
            }
        )
        with patch("usso.lite.oidc.httpx.AsyncClient", return_value=client):
            pair, logged = await auth.login_with_oidc(
                "google",
                callback=f"http://localhost/?code=abc&state={started['state']}",
                state=started["state"],
                state_store=auth._oidc_states,
                session=session,
            )
        assert logged.uid == user.uid
        assert pair.access_token
        payload = auth.verify_token(pair.access_token)
        assert payload.email == "ali@example.com"
        assert AuthSecret.OAUTH.value in (payload.amr or [])


async def test_complete_signup_when_allowed() -> None:
    """Allow signup creates a passwordless LocalUser on first OIDC login."""
    await dispose()
    cfg = LiteConfig(
        database_url="sqlite+aiosqlite:///:memory:",
        oidc_providers={
            "google": OidcProviderConfig(
                client_id="cid", client_secret="csecret"
            )
        },
        oidc_allow_signup=True,
        oidc_default_roles=["viewer"],
        default_scopes=["read:media"],
    )
    auth = LiteAuth(cfg)
    configure(cfg.database_url)
    await init_db()
    async for session in get_session():
        started = auth.start_oidc("google", auth._oidc_states)
        client = _mock_http(
            userinfo={
                "email": "new@example.com",
                "email_verified": True,
                "name": "New",
            }
        )
        with patch("usso.lite.oidc.httpx.AsyncClient", return_value=client):
            pair, user = await auth.login_with_oidc(
                "google",
                callback=f"code=xyz&state={started['state']}",
                state=started["state"],
                state_store=auth._oidc_states,
                session=session,
            )
        assert pair.access_token
        assert user.name == "New"
        assert user.roles == ["viewer"]
        resp = await auth.to_user_response(user, session)
        assert "password" not in resp.credential_methods
        assert "email:new@example.com" in resp.identifiers


async def test_complete_signup_disabled_rejects(
    lite_oidc_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Missing users are rejected when oidc_allow_signup is False."""
    _cfg, auth = lite_oidc_setup
    async for session in get_session():
        started = auth.start_oidc("google", auth._oidc_states)
        client = _mock_http(
            userinfo={"email": "missing@example.com", "email_verified": True}
        )
        with (
            patch("usso.lite.oidc.httpx.AsyncClient", return_value=client),
            pytest.raises(USSOException) as exc_info,
        ):
            await auth.login_with_oidc(
                "google",
                callback=f"code=xyz&state={started['state']}",
                state=started["state"],
                state_store=auth._oidc_states,
                session=session,
            )
        assert exc_info.value.status_code == 403
        assert exc_info.value.error_code == "oidc_user_not_found"


async def test_complete_email_not_verified(
    lite_oidc_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Reject logins when the provider reports email_verified=false."""
    _cfg, auth = lite_oidc_setup
    async for session in get_session():
        started = auth.start_oidc("google", auth._oidc_states)
        client = _mock_http(
            userinfo={
                "email": "ali@example.com",
                "email_verified": False,
            }
        )
        with (
            patch("usso.lite.oidc.httpx.AsyncClient", return_value=client),
            pytest.raises(USSOException) as exc_info,
        ):
            await auth.login_with_oidc(
                "google",
                callback=f"code=xyz&state={started['state']}",
                state=started["state"],
                state_store=auth._oidc_states,
                session=session,
            )
        assert exc_info.value.error_code == "oidc_email_not_verified"


async def test_complete_wrong_state(
    lite_oidc_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Reject callbacks with an unknown CSRF state."""
    _cfg, auth = lite_oidc_setup
    async for session in get_session():
        auth.start_oidc("google", auth._oidc_states)
        with pytest.raises(USSOException) as exc_info:
            await auth.login_with_oidc(
                "google",
                callback="code=xyz&state=wrong",
                state="wrong",
                state_store=auth._oidc_states,
                session=session,
            )
        assert exc_info.value.error_code == "oidc_state_invalid"


async def test_complete_id_token_email_fallback(
    lite_oidc_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """When userinfo lacks email, fall back to unverified id_token payload."""
    _cfg, auth = lite_oidc_setup
    async for session in get_session():
        user = await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="fromid@example.com"
            ),
            password="super-secret-1",
            session=session,
        )
        started = auth.start_oidc("google", auth._oidc_states)
        client = _mock_http(
            id_token=_fake_id_token(email="fromid@example.com"),
            userinfo={},  # no email in userinfo
        )
        with patch("usso.lite.oidc.httpx.AsyncClient", return_value=client):
            pair, logged = await auth.login_with_oidc(
                "google",
                callback=f"code=abc&state={started['state']}",
                state=None,
                state_store=auth._oidc_states,
                session=session,
            )
        assert logged.uid == user.uid
        assert pair.access_token


async def test_complete_inactive_user_rejected(
    lite_oidc_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Inactive accounts cannot complete OIDC login."""
    _cfg, auth = lite_oidc_setup
    async for session in get_session():
        user = await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="dead@example.com"
            ),
            password="super-secret-1",
            session=session,
            is_active=False,
        )
        started = auth.start_oidc("google", auth._oidc_states)
        client = _mock_http(
            userinfo={"email": "dead@example.com", "email_verified": True}
        )
        with (
            patch("usso.lite.oidc.httpx.AsyncClient", return_value=client),
            pytest.raises(USSOException) as exc_info,
        ):
            await auth.login_with_oidc(
                "google",
                callback=f"code=abc&state={started['state']}",
                state=started["state"],
                state_store=auth._oidc_states,
                session=session,
            )
        assert exc_info.value.error_code == "user_not_active"
        assert user.uid


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------


def test_router_oidc_start_and_complete() -> None:
    """Exercise OIDC start + complete via the FastAPI router."""
    app = FastAPI()
    for exc, handler in EXCEPTION_HANDLERS.items():
        app.add_exception_handler(exc, handler)
    cfg = LiteConfig(
        database_url="sqlite+aiosqlite:///:memory:",
        oidc_providers={
            "google": OidcProviderConfig(
                client_id="cid", client_secret="csecret"
            )
        },
        oidc_allow_signup=True,
        oidc_default_roles=["member"],
    )
    app.include_router(create_lite_router(cfg))
    client = TestClient(app)

    start = client.post("/auth/oidc/start", json={"provider": "google"})
    assert start.status_code == 200
    body = start.json()
    assert "authorization_url" in body
    assert "drive" not in body["authorization_url"].lower()
    state = body["state"]

    token_resp = MagicMock()
    token_resp.raise_for_status = MagicMock()
    token_resp.json.return_value = {
        "access_token": "at",
        "token_type": "Bearer",
    }
    token_resp.is_success = True
    token_resp.status_code = 200

    info_resp = MagicMock()
    info_resp.raise_for_status = MagicMock()
    info_resp.json.return_value = {
        "email": "router@example.com",
        "email_verified": True,
        "name": "Router",
    }
    info_resp.is_success = True
    info_resp.status_code = 200

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None
    mock_client.post.return_value = token_resp
    mock_client.get.return_value = info_resp

    with patch("usso.lite.oidc.httpx.AsyncClient", return_value=mock_client):
        complete = client.post(
            "/auth/oidc/complete",
            json={
                "provider": "google",
                "callback": f"http://localhost/?code=abc&state={state}",
                "state": state,
            },
        )
    assert complete.status_code == 200
    assert complete.json()["access_token"]
    assert complete.json()["name"] == "Router"

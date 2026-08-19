"""Coverage tests for the asynchronous USSO HTTP client."""

import time
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from httpx import MockTransport, Request, Response
from usso_jwt import sign
from usso_jwt.algorithms import AbstractKey, EdDSAKey
from usso_jwt.config import JWTConfig
from usso_jwt.schemas import JWT

from src.usso.client import AsyncUssoClient
from src.usso.utils import agent


def _response(
    json_data: dict, *, request: httpx.Request | None = None
) -> httpx.Response:
    """Build an httpx.Response that supports raise_for_status."""
    if request is None:
        request = httpx.Request("POST", "http://test.local")
    return httpx.Response(200, json=json_data, request=request)


def _user_payload(uid: str = "u1") -> dict:
    """Build a minimal valid UserResponse payload."""
    return {
        "uid": uid,
        "created_at": "2024-01-01T00:00:00",
        "updated_at": "2024-01-01T00:00:00",
        "is_deleted": False,
        "tenant_id": "t1",
        "roles": ["admin"],
        "name": "Alice",
    }


def _make_client(
    handler: Callable[[Request], Response],
    **kwargs: Any,
) -> AsyncUssoClient:
    """Build an AsyncUssoClient backed by a MockTransport."""
    kwargs.setdefault("api_key", "test-key")
    return AsyncUssoClient(transport=MockTransport(handler), **kwargs)


def _agent_key() -> str:
    """Return a PEM Ed25519 private key for agent tests."""
    return EdDSAKey.generate().private_pem().decode()


def _signed_future_token() -> str:
    """Return a signed JWT with future expiry for refresh flows."""
    key = EdDSAKey.generate()
    now = int(time.time())
    return sign.generate_jwt(
        header={"alg": "EdDSA", "typ": "JWT"},
        payload={"sub": "u1", "exp": now + 600, "iat": now},
        key=key.private_der(),
        alg="EdDSA",
    )


def _signed_access_token() -> tuple[str, AbstractKey]:
    """Return a signed JWT with future expiry and its signing key."""
    key = EdDSAKey.generate()
    now = int(time.time())
    token = sign.generate_jwt(
        header={"alg": "EdDSA", "typ": "JWT"},
        payload={"sub": "u1", "exp": now + 600, "iat": now},
        key=key.private_der(),
        alg="EdDSA",
    )
    return token, key


def _mock_verify(monkeypatch: pytest.MonkeyPatch) -> None:
    """Avoid network JWKS lookups by faking token verification."""
    monkeypatch.setattr(JWT, "verify", lambda self, **kw: True)


def _refresh_payload() -> dict:
    """Return a refresh response payload with valid tokens."""
    return {
        "access_token": _signed_future_token(),
        "token": {"refresh_token": _signed_future_token()},
    }


async def test_init_sets_api_key_header() -> None:
    """Initializing with an API key populates the request headers."""
    client = _make_client(lambda request: _response({}))
    assert client.api_key == "test-key"
    assert client.headers.get("x-api-key") == "test-key"
    await client.aclose()


async def test_handle_refresh_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_handle_refresh_response extracts tokens and updates headers."""
    _mock_verify(monkeypatch)
    client = _make_client(lambda request: _response({}))
    response = _response(_refresh_payload())
    data = client._handle_refresh_response(response)
    assert data["access_token"]
    assert client.access_token is not None
    assert client._refresh_token is not None
    await client.aclose()


async def test_refresh_sync(monkeypatch: pytest.MonkeyPatch) -> None:
    """_refresh_sync refreshes synchronously using httpx.post."""
    _mock_verify(monkeypatch)
    monkeypatch.setattr(
        httpx,
        "post",
        lambda url, **kwargs: _response(_refresh_payload()),
    )
    client = _make_client(
        lambda request: _response({}),
        api_key=None,
        refresh_token=_signed_future_token(),
    )
    assert client.access_token is not None
    await client.aclose()


async def test_refresh_async(monkeypatch: pytest.MonkeyPatch) -> None:
    """_refresh refreshes asynchronously through the client transport."""
    _mock_verify(monkeypatch)
    client = _make_client(lambda request: _response(_refresh_payload()))
    client._refresh_token = JWT(
        token=_signed_future_token(),
        config=JWTConfig(jwks_url="https://sso.usso.io/jwks.json"),
    )
    data = await client._refresh()
    assert data["access_token"]
    await client.aclose()


async def test_get_session_with_api_key() -> None:
    """get_session short-circuits when API key auth is configured."""
    client = _make_client(lambda request: _response({}))
    assert await client.get_session() is client
    await client.aclose()


async def test_request_forwards_to_httpx() -> None:
    """_request authenticates the session and delegates to httpx."""
    client = _make_client(lambda request: _response({"ok": True}))
    response = await client._request("GET", "/api/sso/v1/users")
    assert response.status_code == 200
    await client.aclose()


async def test_use_agent_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """use_agent_token exchanges an agent JWT for an access token."""

    async def _fake_exchange(jwt: str) -> str:
        return "agent-AT"

    monkeypatch.setattr(agent, "get_agent_token_async", _fake_exchange)
    client = _make_client(
        lambda request: _response({
            "scopes": ["read:users"],
            "tenant_id": "t1",
        }),
        api_key=None,
        agent_id="agent-1",
        agent_private_key=_agent_key(),
    )
    token = await client.use_agent_token(scopes=["read:users"], aud="sso")
    assert token == "agent-AT"
    assert client.access_token is not None
    await client.aclose()


async def test_get_users() -> None:
    """get_users returns parsed UserResponse items."""
    client = _make_client(
        lambda request: _response({
            "items": [_user_payload("u1"), _user_payload("u2")]
        })
    )
    users = await client.get_users()
    assert len(users) == 2
    await client.aclose()


async def test_create_users() -> None:
    """create_users posts a payload and parses the response."""
    client = _make_client(lambda request: _response(_user_payload()))
    user = await client.create_users({"name": "Alice"})
    assert user.uid == "u1"
    await client.aclose()


async def test_get_api_key_scopes() -> None:
    """_get_api_key fetches and returns API key scopes."""
    client = _make_client(
        lambda request: _response({"scopes": ["read:users"]})
    )
    assert await client._get_api_key() == {"scopes": ["read:users"]}
    await client.aclose()


async def test_get_agent_scopes() -> None:
    """_get_agent fetches and returns agent scopes."""
    client = _make_client(
        lambda request: _response({"scopes": ["read:users"]}),
        api_key=None,
        agent_id="agent-1",
        agent_private_key=_agent_key(),
    )
    assert await client._get_agent() == {"scopes": ["read:users"]}
    await client.aclose()


async def test_get_scopes_from_api_key() -> None:
    """_get_scopes falls back to the API key endpoint."""
    client = _make_client(
        lambda request: _response({"scopes": ["read:users"]})
    )
    assert await client._get_scopes() == ["read:users"]
    await client.aclose()


async def test_get_scopes_from_agent() -> None:
    """_get_scopes falls back to the agent endpoint."""
    client = _make_client(
        lambda request: _response({"scopes": ["read:users"]}),
        api_key=None,
        agent_id="agent-1",
        agent_private_key=_agent_key(),
    )
    assert await client._get_scopes() == ["read:users"]
    await client.aclose()


async def test_get_token_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    """_get_token uses an agent token when credentials exist."""

    async def _fake_exchange(jwt: str) -> str:
        return "agent-AT"

    monkeypatch.setattr(agent, "get_agent_token_async", _fake_exchange)
    client = _make_client(
        lambda request: _response({
            "scopes": ["read:users"],
            "tenant_id": "t1",
        }),
        api_key=None,
        agent_id="agent-1",
        agent_private_key=_agent_key(),
    )
    token = await client._get_token(scopes=["read:users"])
    assert token == "agent-AT"
    await client.aclose()


async def test_refresh_async_without_token() -> None:
    """_refresh raises when no refresh token is configured."""
    client = _make_client(lambda request: _response({}))
    with pytest.raises(ValueError):
        await client._refresh()
    await client.aclose()


async def test_use_agent_token_missing_credentials() -> None:
    """use_agent_token raises when agent credentials are absent."""
    client = _make_client(lambda request: _response({}))
    with pytest.raises(ValueError):
        await client.use_agent_token(scopes=["read:users"], aud="sso")
    await client.aclose()


async def test_get_session_refreshes_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """get_session refreshes when the access token is missing."""
    _mock_verify(monkeypatch)
    client = _make_client(lambda request: _response(_refresh_payload()))
    client._refresh_token = JWT(
        token=_signed_future_token(),
        config=JWTConfig(jwks_url="https://sso.usso.io/jwks.json"),
    )
    client.api_key = None
    assert await client.get_session() is client
    assert client.access_token is not None
    await client.aclose()


async def test_get_scopes_from_valid_access_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_get_scopes reads scopes from a valid access token."""
    client = _make_client(lambda request: _response({}))
    token, key = _signed_access_token()
    client.access_token = JWT(
        token=token,
        config=JWTConfig(key=key.jwk()),
    )
    assert await client._get_scopes() == []
    await client.aclose()


async def test_get_scopes_from_refresh_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_get_scopes falls back to the refresh token endpoint."""
    _mock_verify(monkeypatch)
    client = _make_client(lambda request: _response(_refresh_payload()))
    client._refresh_token = JWT(
        token=_signed_future_token(),
        config=JWTConfig(jwks_url="https://sso.usso.io/jwks.json"),
    )
    client.access_token = None
    client.api_key = None
    assert await client._get_scopes() == []
    await client.aclose()


async def test_get_token_missing_agent() -> None:
    """_get_token returns None when no agent credentials are configured."""
    client = _make_client(
        lambda request: _response({"scopes": ["read:users"]}),
        api_key="key",
    )
    assert await client._get_token(scopes=["read:users"]) is None
    await client.aclose()

"""Coverage tests for the synchronous USSO HTTP client."""

import time
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from httpx import MockTransport
from usso_jwt import sign
from usso_jwt.algorithms import AbstractKey, EdDSAKey
from usso_jwt.config import JWTConfig
from usso_jwt.schemas import JWT

from src.usso.client import UssoClient
from src.usso.enums import AuthIdentifier
from src.usso.utils import agent


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
    handler: Callable[[httpx.Request], httpx.Response],
    **kwargs: Any,
) -> UssoClient:
    """Build a UssoClient backed by a MockTransport."""
    kwargs.setdefault("api_key", "test-key")
    return UssoClient(transport=MockTransport(handler), **kwargs)


def _agent_key() -> str:
    """Return a PEM Ed25519 private key for agent tests."""
    return EdDSAKey.generate().private_pem().decode()


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


def test_init_sets_api_key_header() -> None:
    """Initializing with an API key populates the request headers."""
    client = _make_client(lambda request: httpx.Response(200, json={}))
    assert client.api_key == "test-key"
    assert client.headers.get("x-api-key") == "test-key"
    client.close()


def test_refresh_without_token_raises() -> None:
    """_refresh raises ValueError when no refresh token is available."""
    client = _make_client(lambda request: httpx.Response(200, json={}))
    with pytest.raises(ValueError):
        client._refresh()
    client.close()


def _signed_future_token() -> str:
    """Return a signed JWT with future expiry for refresh flows."""
    return _signed_access_token()[0]


def _response(
    json_data: dict, *, request: httpx.Request | None = None
) -> httpx.Response:
    """Build an httpx.Response that supports raise_for_status."""
    if request is None:
        request = httpx.Request("POST", "http://test.local")
    return httpx.Response(200, json=json_data, request=request)


def _mock_verify(monkeypatch: pytest.MonkeyPatch) -> None:
    """Avoid network JWKS lookups by faking token verification."""
    monkeypatch.setattr(JWT, "verify", lambda self, **kw: True)


def test_refresh_exchanges_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """_refresh exchanges the refresh token for a new access token."""
    _mock_verify(monkeypatch)

    def fake_post(url: str, **kwargs: object) -> httpx.Response:
        return _response({
            "access_token": _signed_future_token(),
            "refresh_token": "RT",
        })

    monkeypatch.setattr(httpx, "post", fake_post)
    client = _make_client(
        lambda request: _response({}),
        api_key=None,
        refresh_token=_signed_future_token(),
    )
    assert client.access_token is not None
    assert client.headers.get("Authorization") is not None
    client.close()


def test_get_session_with_api_key_returns_self() -> None:
    """get_session short-circuits when API key auth is configured."""
    client = _make_client(lambda request: httpx.Response(200, json={}))
    assert client.get_session() is client
    client.close()


def test_get_session_refreshes_when_no_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """get_session refreshes the access token when it is missing."""
    _mock_verify(monkeypatch)
    monkeypatch.setattr(
        httpx,
        "post",
        lambda url, **kwargs: _response({
            "access_token": _signed_future_token(),
            "refresh_token": "RT",
        }),
    )
    client = _make_client(
        lambda request: _response({}),
        api_key=None,
        refresh_token=_signed_future_token(),
    )
    client.access_token = None
    assert client.get_session() is client
    client.close()


def test_request_forwards_to_httpx() -> None:
    """_request authenticates the session and delegates to httpx."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(200, json={"ok": True})

    client = _make_client(handler)
    response = client._request("GET", "/api/sso/v1/users")
    assert response.status_code == 200
    assert calls == ["/api/sso/v1/users"]
    client.close()


def test_use_agent_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """use_agent_token exchanges an agent JWT for an access token."""
    monkeypatch.setattr(agent, "get_agent_token", lambda jwt: "agent-AT")
    client = _make_client(
        lambda request: httpx.Response(200, json={"tenant_id": "t1"}),
        api_key=None,
        agent_id="agent-1",
        agent_private_key=_agent_key(),
    )
    token = client.use_agent_token(scopes=["read:users"], aud="sso")
    assert token == "agent-AT"
    assert client.access_token is not None
    client.close()


def test_use_agent_token_missing_credentials() -> None:
    """use_agent_token raises when agent credentials are absent."""
    client = _make_client(lambda request: httpx.Response(200, json={}))
    with pytest.raises(ValueError):
        client.use_agent_token(scopes=["read:users"], aud="sso")
    client.close()


def test_get_users() -> None:
    """get_users returns parsed UserResponse items."""
    client = _make_client(
        lambda request: httpx.Response(
            200, json={"items": [_user_payload("u1"), _user_payload("u2")]}
        )
    )
    users = client.get_users()
    assert len(users) == 2
    assert users[0].name == "Alice"
    client.close()


def test_create_users() -> None:
    """create_users posts a payload and parses the response."""
    client = _make_client(
        lambda request: httpx.Response(200, json=_user_payload())
    )
    user = client.create_users({"name": "Alice"})
    assert user.uid == "u1"
    client.close()


def test_get_profile() -> None:
    """get_profile fetches a profile by user id."""
    client = _make_client(
        lambda request: httpx.Response(200, json={"bio": "hi"})
    )
    profile = client.get_profile("u1")
    assert profile == {"bio": "hi"}
    client.close()


def test_add_identifier() -> None:
    """add_identifier posts a new identifier for a user."""
    client = _make_client(
        lambda request: httpx.Response(200, json={"ok": True})
    )
    result = client.add_identifier("u1", AuthIdentifier.EMAIL, "a@b.com")
    assert result == {"ok": True}
    client.close()


def test_get_api_key_scopes() -> None:
    """_get_api_key fetches and returns API key scopes."""
    client = _make_client(
        lambda request: httpx.Response(200, json={"scopes": ["read:users"]})
    )
    assert client._get_api_key() == {"scopes": ["read:users"]}
    client.close()


def test_get_agent_scopes() -> None:
    """_get_agent fetches and returns agent scopes."""
    client = _make_client(
        lambda request: httpx.Response(200, json={"scopes": ["read:users"]}),
        api_key=None,
        agent_id="agent-1",
        agent_private_key=_agent_key(),
    )
    assert client._get_agent() == {"scopes": ["read:users"]}
    client.close()


def test_get_scopes_from_valid_access_token() -> None:
    """_get_scopes reads scopes from a valid access token."""
    client = _make_client(lambda request: httpx.Response(200, json={}))
    token, key = _signed_access_token()
    client.access_token = JWT(
        token=token,
        config=JWTConfig(key=key.jwk()),
    )
    assert client._get_scopes() == []
    client.close()


def test_get_scopes_from_api_key() -> None:
    """_get_scopes falls back to the API key endpoint."""
    client = _make_client(
        lambda request: httpx.Response(200, json={"scopes": ["read:users"]})
    )
    assert client._get_scopes() == ["read:users"]
    client.close()


def test_get_scopes_from_agent() -> None:
    """_get_scopes falls back to the agent endpoint."""
    client = _make_client(
        lambda request: httpx.Response(200, json={"scopes": ["read:users"]}),
        api_key=None,
        agent_id="agent-1",
        agent_private_key=_agent_key(),
    )
    assert client._get_scopes() == ["read:users"]
    client.close()


def test_get_scopes_from_refresh_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_get_scopes falls back to the refresh token endpoint."""
    _mock_verify(monkeypatch)
    monkeypatch.setattr(
        httpx,
        "post",
        lambda url, **kwargs: _response({
            "access_token": _signed_future_token(),
            "refresh_token": "RT",
        }),
    )
    client = _make_client(
        lambda request: _response({}),
        api_key=None,
        refresh_token=_signed_future_token(),
    )
    client.access_token = None
    assert client._get_scopes() == []
    client.close()


def test_get_token_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    """_get_token uses an agent token when credentials exist."""
    monkeypatch.setattr(agent, "get_agent_token", lambda jwt: "agent-AT")
    client = _make_client(
        lambda request: httpx.Response(
            200, json={"scopes": ["read:users"], "tenant_id": "t1"}
        ),
        api_key=None,
        agent_id="agent-1",
        agent_private_key=_agent_key(),
    )
    token = client._get_token(scopes=["read:users"])
    assert token == "agent-AT"
    client.close()


def test_get_token_missing_agent() -> None:
    """_get_token returns None when no agent credentials are configured."""
    client = _make_client(
        lambda request: httpx.Response(200, json={"scopes": ["read:users"]}),
        api_key="key",
    )
    assert client._get_token(scopes=["read:users"]) is None
    client.close()

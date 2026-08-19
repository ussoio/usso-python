"""Coverage tests for the FastAPI integration and agent utilities."""

import json
import time
from collections.abc import Callable, Coroutine
from typing import Any

import httpx
import pytest
from starlette.requests import Request
from starlette.websockets import WebSocket
from usso_jwt import sign
from usso_jwt.algorithms import AbstractKey
from usso_jwt.utils import b64url_encode

from src.usso import UserData
from src.usso.config import APIHeaderConfig, AuthConfig
from src.usso.exceptions import PermissionDenied, USSOException
from src.usso.integrations.fastapi import (
    USSOAuthentication,
    usso_exception_handler,
)


def _make_request(
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> Request:
    """Build a real Starlette Request with the given headers and cookies."""
    header_bytes = [
        (key.lower().encode(), value.encode())
        for key, value in (headers or {}).items()
    ]
    cookie_header = "; ".join(
        f"{key}={value}" for key, value in (cookies or {}).items()
    )
    if cookie_header:
        header_bytes.append((b"cookie", cookie_header.encode()))
    scope: dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": header_bytes,
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
    }
    return Request(scope)


def _make_websocket(
    headers: dict[str, str] | None = None,
) -> WebSocket:
    """Build a real Starlette WebSocket with the given headers."""
    header_bytes = [
        (key.lower().encode(), value.encode())
        for key, value in (headers or {}).items()
    ]
    scope: dict[str, Any] = {
        "type": "websocket",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "scheme": "ws",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": header_bytes,
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
        "subprotocols": [],
    }

    async def _receive() -> dict[str, Any]:
        return {"type": "websocket.disconnect"}

    async def _send(message: Any) -> None:
        return None

    return WebSocket(scope, receive=_receive, send=_send)


def _bearer_request(token: str) -> Request:
    return _make_request(headers={"Authorization": f"Bearer {token}"})


def _api_key_request(key: str = "my-api-key") -> Request:
    return _make_request(headers={"x-api-key": key})


def _build_token(
    key: AbstractKey,
    *,
    scopes: list[str] | None = None,
) -> str:
    now = int(time.time())
    payload: dict[str, object] = {
        "sub": "user-1",
        "iat": now,
        "exp": now + 600,
    }
    if scopes is not None:
        payload["scopes"] = scopes
    return sign.generate_jwt(
        header={"alg": key.algorithm, "typ": "JWT"},
        payload=payload,
        key=key.private_der(),
        alg=key.algorithm,
    )


def _make_auth(
    test_key: AbstractKey,
    *,
    api_key_verifier: Callable[[str], UserData] | None = None,
    api_key_verifier_async: (
        Callable[[str], Coroutine[Any, Any, UserData]] | None
    ) = None,
) -> USSOAuthentication:
    config = AuthConfig(
        key=test_key.jwk(),
        api_key_header=APIHeaderConfig(
            api_key_verifier=api_key_verifier,
            api_key_verifier_async=api_key_verifier_async,
        ),
    )
    return USSOAuthentication(jwt_config=config)


def _jwe_token() -> str:
    segment = b64url_encode(b"not-a-real-jwe-segment")
    return ".".join([segment] * 5)


def test_authentication_callable(test_key: AbstractKey) -> None:
    """USSOAuthentication instance is directly callable as a dependency."""
    auth = _make_auth(test_key)
    request = _bearer_request(_build_token(test_key))
    user = auth(request)
    assert user is not None
    assert user.uid == "user-1"


def test_get_request_api_key(test_key: AbstractKey) -> None:
    """API key extraction from the request header."""
    auth = _make_auth(test_key)
    assert auth.get_request_api_key(_api_key_request("secret-key")) == (
        "secret-key"
    )
    assert auth.get_request_api_key(_bearer_request("token")) is None


def test_jwe_token_sync_raises(test_key: AbstractKey) -> None:
    """A compact JWE token is rejected synchronously."""
    auth = _make_auth(test_key)
    with pytest.raises(USSOException):
        auth.usso_access_security(_bearer_request(_jwe_token()))


def test_api_key_sync(test_key: AbstractKey) -> None:
    """Synchronous API key authentication via header."""
    auth = _make_auth(test_key, api_key_verifier=lambda key: UserData(sub=key))
    request = _api_key_request()
    user = auth.usso_access_security(request)
    assert user is not None
    assert user.uid == "my-api-key"


def test_non_jwt_bearer_treated_as_api_key(test_key: AbstractKey) -> None:
    """A non-JWT bearer token falls back to API key verification."""
    auth = _make_auth(test_key, api_key_verifier=lambda key: UserData(sub=key))
    user = auth.usso_access_security(_bearer_request("raw-token-value"))
    assert user is not None
    assert user.uid == "raw-token-value"


async def test_async_jwt_and_no_token(test_key: AbstractKey) -> None:
    """Async authentication with a valid token and with no token."""
    auth = _make_auth(test_key)
    user = await auth.usso_access_security_async(
        _bearer_request(_build_token(test_key))
    )
    assert user is not None
    assert user.uid == "user-1"

    auth_relaxed = _make_auth(test_key)
    auth_relaxed.raise_exception = False
    assert (
        await auth_relaxed.usso_access_security_async(_make_request()) is None
    )


async def test_async_jwe_raises(test_key: AbstractKey) -> None:
    """A compact JWE token is rejected asynchronously."""
    auth = _make_auth(test_key)
    with pytest.raises(USSOException):
        await auth.usso_access_security_async(_bearer_request(_jwe_token()))


async def test_async_api_key(test_key: AbstractKey) -> None:
    """Async API key authentication via header."""

    async def verifier(  # awaited by client
        key: str,
    ) -> UserData:
        return UserData(sub=key)

    auth = _make_auth(test_key, api_key_verifier_async=verifier)
    user = await auth.usso_access_security_async(_api_key_request())
    assert user is not None
    assert user.uid == "my-api-key"


async def test_async_non_jwt_bearer(test_key: AbstractKey) -> None:
    """Async fallback to API key for a non-JWT bearer token."""

    async def verifier(  # awaited by client
        key: str,
    ) -> UserData:
        return UserData(sub=key)

    auth = _make_auth(test_key, api_key_verifier_async=verifier)
    user = await auth.usso_access_security_async(_bearer_request("raw-key"))
    assert user is not None
    assert user.uid == "raw-key"


def test_websocket_api_key_and_no_token(test_key: AbstractKey) -> None:
    """WebSocket authentication with an API key and with no token."""
    auth = _make_auth(test_key, api_key_verifier=lambda key: UserData(sub=key))
    user = auth.jwt_access_security_ws(_make_websocket({"x-api-key": "key-1"}))
    assert user is not None

    auth_relaxed = _make_auth(test_key)
    auth_relaxed.raise_exception = False
    assert auth_relaxed.jwt_access_security_ws(_make_websocket()) is None


def test_websocket_jwe_raises(test_key: AbstractKey) -> None:
    """A compact JWE token is rejected over WebSocket."""
    auth = _make_auth(test_key)
    with pytest.raises(USSOException):
        auth.jwt_access_security_ws(
            _make_websocket({"Authorization": f"Bearer {_jwe_token()}"})
        )


def test_websocket_raw_bearer_as_api_key(test_key: AbstractKey) -> None:
    """A raw bearer token over WebSocket falls back to API key auth."""
    auth = _make_auth(test_key, api_key_verifier=lambda key: UserData(sub=key))
    user = auth.jwt_access_security_ws(
        _make_websocket({"Authorization": "Bearer raw-key-value"})
    )
    assert user is not None
    assert user.uid == "raw-key-value"


def test_authorize_allows_and_denies(test_key: AbstractKey) -> None:
    """The authorize dependency enforces scope-based access."""
    auth = _make_auth(test_key)
    authorize = auth.authorize(action="read", resource_path="users")

    user = authorize(
        _bearer_request(_build_token(test_key, scopes=["read:users"]))
    )
    assert user is not None

    denied = _make_auth(test_key).authorize(
        action="read", resource_path="users"
    )
    with pytest.raises(PermissionDenied):
        denied(_bearer_request(_build_token(test_key, scopes=["read:other"])))


def test_exception_handler_localized() -> None:
    """The exception handler honours the accept-language header."""
    exc = USSOException(
        401,
        error_code="invalid_token",
        message={"en": "Unauthorized", "fa": "احراز هویت ناموفق"},
    )
    request = _make_request(headers={"accept-language": "fa-IR,fa;q=0.9"})
    response = usso_exception_handler(request, exc)
    assert response.status_code == 401
    body = json.loads(bytes(response.body).decode("utf-8"))
    assert body["message"]["fa"] == "احراز هویت ناموفق"


# ---------------------------------------------------------------------------
# Agent utilities
# ---------------------------------------------------------------------------


class _FakeResponse:
    """Fake httpx response used to exercise agent token exchange."""

    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


class _FakeSyncClient:
    """Fake httpx.Client stand-in."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url

    def __enter__(self) -> "_FakeSyncClient":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def post(self, path: str, **kwargs: object) -> _FakeResponse:
        assert path == "/agents/auth"
        return _FakeResponse({"tokens": {"access": "access-token-1"}})


class _FakeAsyncClient:
    """Fake httpx.AsyncClient stand-in."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url

    async def __aenter__(self) -> "_FakeAsyncClient":
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def post(self, path: str, **kwargs: object) -> _FakeResponse:
        assert path == "/agents/auth"
        return _FakeResponse({"tokens": {"access": "access-token-2"}})


def test_generate_agent_jwt_requires_credentials(
    test_key: AbstractKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """generate_agent_jwt raises when credentials are missing."""
    monkeypatch.delenv("AGENT_ID", raising=False)
    monkeypatch.delenv("AGENT_PRIVATE_KEY", raising=False)
    from src.usso.utils.agent import generate_agent_jwt

    with pytest.raises(ValueError):
        generate_agent_jwt(scopes=["read:users"], aud="https://usso.uln.me")


def test_generate_agent_jwt_with_key(
    test_key: AbstractKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """generate_agent_jwt produces a signed JWT when a key is provided."""
    monkeypatch.delenv("AGENT_ID", raising=False)
    monkeypatch.delenv("AGENT_PRIVATE_KEY", raising=False)
    from src.usso.utils.agent import generate_agent_jwt

    pem = test_key.private_pem().decode()
    jwt = generate_agent_jwt(
        scopes=["read:users"],
        aud="https://usso.uln.me",
        tenant_id="t-1",
        agent_id="agent-1",
        private_key=pem,
    )
    assert len(jwt.split(".")) == 3


def test_get_agent_token_sync(monkeypatch: pytest.MonkeyPatch) -> None:
    """get_agent_token exchanges an agent JWT for an access token."""
    import src.usso.utils.agent as agent_module

    monkeypatch.setattr(httpx, "Client", _FakeSyncClient)
    token = agent_module.get_agent_token("some.jwt.token")
    assert token == "access-token-1"


async def test_get_agent_token_async(monkeypatch: pytest.MonkeyPatch) -> None:
    """get_agent_token_async exchanges an agent JWT asynchronously."""
    import src.usso.utils.agent as agent_module

    monkeypatch.setattr(httpx, "AsyncClient", _FakeAsyncClient)
    token = await agent_module.get_agent_token_async("some.jwt.token")
    assert token == "access-token-2"

"""Coverage tests for the USSO client base class."""

import time
from typing import Any

import httpx
import pytest
from httpx import MockTransport
from usso_jwt import sign
from usso_jwt.algorithms import EdDSAKey
from usso_jwt.config import JWTConfig
from usso_jwt.schemas import JWT

from src.usso.client import UssoClient


def _make_client(**kwargs: Any) -> UssoClient:
    """Build a UssoClient backed by a MockTransport."""
    kwargs.setdefault("api_key", "test-key")
    return UssoClient(
        transport=MockTransport(lambda request: httpx.Response(200, json={})),
        **kwargs,
    )


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


def test_base_url_strips_trailing_slash() -> None:
    """The configured base URL has its trailing slash removed."""
    client = _make_client(usso_base_url="https://sso.example.com/")
    assert client.usso_base_url == "https://sso.example.com"
    assert client.usso_refresh_url == (
        "https://sso.example.com/api/sso/v1/auth/refresh"
    )
    client.close()


def test_copy_attributes_from_other_client() -> None:
    """copy_attributes_from replicates auth state from another client."""
    source = _make_client(api_key="key-1", usso_base_url="https://a.io")
    target = _make_client(client=source)
    assert target.api_key == "key-1"
    assert target.usso_base_url == "https://a.io"
    assert target.headers.get("x-api-key") == "key-1"
    source.close()
    target.close()


def test_refresh_token_property_keeps_valid_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid refresh token is preserved by the refresh_token property."""
    monkeypatch.setattr(JWT, "verify", lambda self, **kw: True)
    monkeypatch.setattr(
        httpx,
        "post",
        lambda url, **kwargs: httpx.Response(
            200,
            json={"access_token": "AT", "refresh_token": "RT"},
            request=httpx.Request("POST", "http://test.local"),
        ),
    )
    client = _make_client(
        api_key=None,
        refresh_token=_signed_future_token(),
    )
    assert client._refresh_token is not None
    assert client.refresh_token is not None
    client.close()


def test_refresh_token_property_clears_invalid_token() -> None:
    """An invalid refresh token is cleared by the refresh_token property."""
    client = _make_client(api_key="key-1")
    client._refresh_token = JWT(
        token="not.a.jwt",
        config=JWTConfig(jwks_url="https://sso.usso.io/jwks.json"),
    )
    assert client.refresh_token is None
    client.close()

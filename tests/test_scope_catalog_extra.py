"""Coverage tests for the scope catalog helpers."""

import httpx
import pytest

from usso import scope_catalog as sc
from usso.scope_catalog import (
    fetch_client_credentials_token,
    put_scope_catalog,
    register_scope_catalog,
    scopes_from_resource_paths,
    scopes_from_routers,
)


class _Router:
    """Duck-typed router exposing a resource path."""

    def __init__(self, path: str) -> None:
        self._path = path

    @property
    def resource_path(self) -> str:
        return self._path


def test_scopes_from_resource_paths_skips_empty() -> None:
    """Empty and duplicate resource paths are skipped."""
    result = scopes_from_resource_paths(
        ["", "/users", "users", "files"], actions=["read"]
    )
    scopes = [entry["scope"] for entry in result]
    assert scopes == ["read:users", "read:files"]


def test_scopes_from_routers_callable_path() -> None:
    """A callable resource_path is invoked."""
    router = type(
        "R",
        (),
        {"resource_path": lambda self: "callable/path"},
    )()
    result = scopes_from_routers([router], actions=("read",))
    assert result[0]["scope"] == "read:callable/path"


def test_scopes_from_routers_property_path() -> None:
    """A string resource_path attribute is used directly."""
    result = scopes_from_routers([_Router("users")], actions=("read",))
    assert result[0]["scope"] == "read:users"


class _FakeAsyncClient:
    """Fake httpx.AsyncClient for token exchange and catalog PUT."""

    def __init__(self, json_body: dict, status: int = 200) -> None:
        self._json = json_body
        self._status = status
        self.method = None
        self.url = None

    async def __aenter__(self) -> "_FakeAsyncClient":
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def post(self, url: str, **kwargs: object) -> httpx.Response:
        return httpx.Response(
            self._status,
            json=self._json,
            request=httpx.Request("POST", url),
        )

    async def put(self, url: str, **kwargs: object) -> httpx.Response:
        return httpx.Response(
            self._status,
            json=self._json,
            request=httpx.Request("PUT", url),
        )


async def test_fetch_client_credentials_token_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """fetch_client_credentials_token returns the access token."""
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kw: _FakeAsyncClient({"access_token": "AT"}),
    )
    token = await fetch_client_credentials_token(
        usso_base_url="https://sso.example.com/",
        client_id="cid",
        client_secret="secret",
        oauth_token_path="/oauth/token",
    )
    assert token == "AT"


async def test_fetch_client_credentials_token_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """fetch_client_credentials_token raises when token is absent."""
    monkeypatch.setattr(
        httpx, "AsyncClient", lambda **kw: _FakeAsyncClient({"nope": True})
    )
    with pytest.raises(ValueError):
        await fetch_client_credentials_token(
            usso_base_url="https://sso.example.com",
            client_id="cid",
            client_secret="secret",
        )


async def test_put_scope_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    """put_scope_catalog PUTs the scopes for a service."""
    monkeypatch.setattr(
        httpx, "AsyncClient", lambda **kw: _FakeAsyncClient({})
    )
    await put_scope_catalog(
        usso_base_url="https://sso.example.com",
        service="media",
        scopes=[{"scope": "read:files"}],
        access_token="AT",
    )


async def test_register_scope_catalog_disabled() -> None:
    """register_scope_catalog returns False when disabled."""
    assert (
        await register_scope_catalog(service="media", scopes=[], enabled=False)
        is False
    )


async def test_register_scope_catalog_missing_credentials() -> None:
    """register_scope_catalog returns False without credentials."""
    assert (
        await register_scope_catalog(
            service="media", scopes=[{"scope": "read:files"}]
        )
        is False
    )


async def test_register_scope_catalog_empty_scopes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """register_scope_catalog returns False for empty scopes."""
    monkeypatch.setenv("SCOPE_CATALOG_CLIENT_ID", "cid")
    monkeypatch.setenv("SCOPE_CATALOG_CLIENT_SECRET", "secret")
    assert await register_scope_catalog(service="media", scopes=[]) is False


async def test_register_scope_catalog_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """register_scope_catalog returns False when the push fails."""

    async def _boom(**kwargs: object) -> str:
        raise RuntimeError("push failed")

    monkeypatch.setenv("SCOPE_CATALOG_CLIENT_ID", "cid")
    monkeypatch.setenv("SCOPE_CATALOG_CLIENT_SECRET", "secret")
    monkeypatch.setattr(sc, "fetch_client_credentials_token", _boom)
    assert (
        await register_scope_catalog(
            service="media", scopes=[{"scope": "read:files"}]
        )
        is False
    )

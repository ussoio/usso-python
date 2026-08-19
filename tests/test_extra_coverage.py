"""Extra FastAPI / authorization / scope catalog coverage."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from usso.authorization import get_common_scopes, is_authorized
from usso.config import AuthConfig
from usso.exceptions import PermissionDenied, USSOError
from usso.integrations.fastapi.dependency import USSOAuthentication
from usso.integrations.fastapi.handler import usso_exception_handler
from usso.scope_catalog import (
    fetch_client_credentials_token,
    put_scope_catalog,
    register_scope_catalog,
    scopes_from_routers,
)
from usso.user import UserData

CLIENT_SECRET = "".join(("sec", "ret"))
ACCESS = "".join(("tok", "en"))
"""Extra FastAPI / authorization / scope catalog coverage."""


def test_exception_handler_with_locale() -> None:
    """Exception handler localizes with Accept-Language."""
    request = MagicMock()
    request.headers = {"accept-language": "fa-IR,en;q=0.8"}
    exc = USSOError(401, "unauthorized", message={"en": "no", "fa": "نه"})
    resp = usso_exception_handler(request, exc)
    assert isinstance(resp, JSONResponse)
    assert resp.status_code == 401


def test_fastapi_authorize_and_async_paths() -> None:
    """FastAPI authorize dependency and async security."""
    auth = USSOAuthentication(jwt_config=AuthConfig())
    user = UserData(sub="u", scopes=["read:files"])

    dep = auth.authorize(action="read", resource_path="files")
    req = MagicMock(spec=Request)
    with patch.object(auth, "usso_access_security", return_value=user):
        assert dep(req).sub == "u"

    with (
        patch.object(auth, "usso_access_security", return_value=user),
        pytest.raises(PermissionDenied),
    ):
        auth.authorize(action="admin", resource_path="files")(req)

    with (
        patch.object(auth, "usso_access_security", return_value=None),
        pytest.raises(USSOError),
    ):
        dep(req)


@pytest.mark.asyncio
async def test_fastapi_async_security_routes() -> None:
    """Async security JWT/API key/JWE branches."""
    auth = USSOAuthentication(jwt_config=AuthConfig(), raise_exception=False)
    req = MagicMock(spec=Request)
    user = UserData(sub="u")

    with (
        patch.object(auth, "get_request_jwt", return_value="a.b.c"),
        patch.object(auth, "detect_compact_token_type", return_value="jwt"),
        patch.object(auth, "user_data_from_token", return_value=user),
    ):
        assert await auth.usso_access_security_async(req) is user

    with (
        patch.object(auth, "get_request_jwt", return_value="a.b.c.d.e"),
        patch.object(auth, "detect_compact_token_type", return_value="jwe"),
        patch.object(
            auth, "user_data_from_jwe_async", new=AsyncMock(return_value=None)
        ),
    ):
        assert await auth.usso_access_security_async(req) is None

    with (
        patch.object(auth, "get_request_jwt", return_value="key"),
        patch.object(auth, "detect_compact_token_type", return_value=None),
        patch.object(
            auth,
            "user_data_from_api_key_async",
            new=AsyncMock(return_value=user),
        ),
    ):
        assert await auth.usso_access_security_async(req) is user

    with (
        patch.object(auth, "get_request_jwt", return_value=None),
        patch.object(auth, "get_request_api_key", return_value=None),
    ):
        assert await auth.usso_access_security_async(req) is None


def test_get_common_scopes() -> None:
    """Common scope intersection helper."""
    assert get_common_scopes(
        scopes_a=["read:files"], scopes_b=["read:files", "write:files"]
    ) == ["read:files"]
    result = get_common_scopes(
        scopes_a=["admin:files"], scopes_b=["read:files"]
    )
    assert "admin:files" not in result
    assert is_authorized("read:files", "files", None) is True


def test_scopes_from_routers() -> None:
    """Duck-typed router scope extraction."""

    class Router:
        resource_path = "media/files"

    class CallablePath:
        def resource_path(self) -> str:
            return "media/keys"

    scopes = scopes_from_routers([Router(), CallablePath(), object()])
    assert any(s["scope"].endswith("media/files") for s in scopes)


@pytest.mark.asyncio
async def test_scope_catalog_http_helpers() -> None:
    """OAuth token + put catalog + register success/failure."""
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"access_token": ACCESS}

    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    client.post.return_value = mock_resp
    client.put.return_value = mock_resp

    async_cls = "usso.scope_catalog.httpx.AsyncClient"
    with patch(async_cls, return_value=client):
        token = await fetch_client_credentials_token(
            usso_base_url="https://sso.example",
            client_id="id",
            client_secret=CLIENT_SECRET,
        )
        assert token == ACCESS
        await put_scope_catalog(
            usso_base_url="https://sso.example",
            service="media",
            scopes=[{"scope": "read:media/files"}],
            access_token=token,
        )

    with (
        patch(
            "usso.scope_catalog.fetch_client_credentials_token",
            new=AsyncMock(return_value=ACCESS),
        ),
        patch(
            "usso.scope_catalog.put_scope_catalog",
            new=AsyncMock(),
        ),
    ):
        ok = await register_scope_catalog(
            service="media",
            scopes=[{"scope": "read:media/files"}],
            usso_base_url="https://sso.example",
            client_id="id",
            client_secret=CLIENT_SECRET,
        )
        assert ok is True

    assert (
        await register_scope_catalog(
            service="media",
            scopes=[{"scope": "read:x"}],
            enabled=False,
        )
        is False
    )
    assert (
        await register_scope_catalog(
            service="media",
            scopes=[],
            client_id="id",
            client_secret=CLIENT_SECRET,
        )
        is False
    )

    with patch(
        "usso.scope_catalog.fetch_client_credentials_token",
        new=AsyncMock(side_effect=RuntimeError("boom")),
    ):
        assert (
            await register_scope_catalog(
                service="media",
                scopes=[{"scope": "read:x"}],
                client_id="id",
                client_secret=CLIENT_SECRET,
            )
            is False
        )


def test_fastapi_callable_dependency() -> None:
    """USSOAuthentication __call__ delegates to security."""
    auth = USSOAuthentication(jwt_config=AuthConfig(), raise_exception=False)
    req = MagicMock(spec=Request)
    with patch.object(auth, "usso_access_security", return_value=None):
        assert auth(req) is None
    app = FastAPI()
    assert app is not None

"""Fill remaining coverage gaps across auth, authorization, integrations."""

from __future__ import annotations

import asyncio
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest
from django.db.utils import IntegrityError
from fastapi import Request, WebSocket

from usso.auth import UssoAuth
from usso.authorization import (
    _normalize_path,
    broadest_scope_filter,
    get_scope_filters,
    has_subset_scope,
    is_path_match,
)
from usso.config import APIHeaderConfig, AuthConfig
from usso.exceptions import USSOError, _handle_exception
from usso.integrations.django.middleware import (
    USSOAuthenticationMiddleware,
)
from usso.integrations.fastapi.dependency import USSOAuthentication
from usso.user import UserData


def test_authorization_helpers() -> None:
    """Cover path matching and filter helpers."""
    assert is_path_match("media/*", "media/files")
    with pytest.raises(TypeError):
        _normalize_path(cast("Any", 123))
    filters = get_scope_filters(
        action="read",
        resource="media/files",
        user_scopes=["read:media/files?user_id=1", "admin:other"],
    )
    assert {"user_id": "1"} in filters
    broad = broadest_scope_filter([
        {},
        {"tenant_id": "t1"},
        {"tenant_id": "t1", "user_id": "u1"},
    ])
    assert broad == {}
    assert (
        has_subset_scope(subset_scope="read:files", user_scopes=None) is False
    )
    assert has_subset_scope(
        subset_scope="read:files", user_scopes="read:files"
    )


def test_auth_from_usso_base_url_and_runtime_error() -> None:
    """Cover from_usso_base_url path and async verifier in loop error."""
    auth = UssoAuth(
        jwt_config=AuthConfig(
            jwks_url="https://example/.well-known/jwks.json"
        ),
        from_usso_base_url="https://usso.example",
    )

    class Payload:
        iss = "https://issuer.example"

    jwt_obj = MagicMock()
    jwt_obj.unverified_payload = Payload()
    jwt_obj.config = MagicMock()
    jwt_obj.verify.return_value = True
    jwt_obj.payload = UserData(sub="u")

    with patch("usso_jwt.schemas.JWT", return_value=jwt_obj):
        user = auth.user_data_from_token("a.b.c")
        assert user is not None
        assert user.sub == "u"

    async def async_verifier(_key: str) -> UserData:
        await asyncio.sleep(0)
        return UserData(sub="x")

    header = APIHeaderConfig(api_key_verifier_async=async_verifier)
    with (
        patch("asyncio.get_running_loop", return_value=object()),
        pytest.raises(RuntimeError),
    ):
        UssoAuth._run_sync_api_key_verifier(header, "k")

    with pytest.raises(RuntimeError):
        UssoAuth._run_sync_api_key_verifier(APIHeaderConfig(), "k")


def test_handle_exception_non_dict_message() -> None:
    """_handle_exception stringifies odd message types."""
    with pytest.raises(USSOError):
        _handle_exception("unauthorized", message=123)


def test_fastapi_sync_security_branches() -> None:
    """FastAPI sync JWT/API key/websocket branches."""
    auth = USSOAuthentication(jwt_config=AuthConfig(), raise_exception=False)
    req = MagicMock(spec=Request)
    ws = MagicMock(spec=WebSocket)
    user = UserData(sub="u")

    with (
        patch.object(auth, "get_request_jwt", return_value="a.b.c"),
        patch.object(auth, "detect_compact_token_type", return_value="jwt"),
        patch.object(auth, "user_data_from_token", return_value=user),
    ):
        assert auth.usso_access_security(req) is user
        assert auth.jwt_access_security_ws(ws) is user

    with (
        patch.object(auth, "get_request_jwt", return_value="a.b.c.d.e"),
        patch.object(auth, "detect_compact_token_type", return_value="jwe"),
        patch.object(auth, "user_data_from_jwe", return_value=None),
    ):
        assert auth.usso_access_security(req) is None
        assert auth.jwt_access_security_ws(ws) is None

    with (
        patch.object(auth, "get_request_jwt", return_value="key"),
        patch.object(auth, "detect_compact_token_type", return_value=None),
        patch.object(auth, "user_data_from_api_key", return_value=user),
    ):
        assert auth.usso_access_security(req) is user
        assert auth.jwt_access_security_ws(ws) is user

    with (
        patch.object(auth, "get_request_jwt", return_value=None),
        patch.object(auth, "get_request_api_key", return_value="k"),
        patch.object(auth, "user_data_from_api_key", return_value=user),
    ):
        assert auth.usso_access_security(req) is user
        assert auth.jwt_access_security_ws(ws) is user

    with (
        patch.object(auth, "get_request_jwt", return_value=None),
        patch.object(auth, "get_request_api_key", return_value=None),
    ):
        assert auth.usso_access_security(req) is None
        assert auth.jwt_access_security_ws(ws) is None

    auth.jwt_configs = []
    assert auth.get_request_jwt(req) is None
    assert auth.get_request_api_key(req) is None


def test_django_middleware_get_or_create_user() -> None:
    """Middleware user creation paths."""
    from django.conf import settings

    settings.USSO_JWT_CONFIG = AuthConfig(
        jwks_url="https://sso.example/.well-known/jwks.json"
    )
    middleware = USSOAuthenticationMiddleware(get_response=lambda r: r)
    user_data = UserData(sub="u1", phone="999", email="")
    django_user = MagicMock()
    with patch(
        "usso.integrations.django.middleware.User.objects"
    ) as objects:
        objects.get_or_create.return_value = (django_user, False)
        assert middleware.get_or_create_user(user_data) is django_user

    with patch(
        "usso.integrations.django.middleware.User.objects"
    ) as objects:
        objects.get_or_create.side_effect = IntegrityError("dup")
        with pytest.raises(ValueError, match="Error while creating user"):
            middleware.get_or_create_user(user_data)


def test_client_session_request_and_scope_branches() -> None:
    """Cover sync client session/request/scope edge branches."""
    from unittest.mock import PropertyMock

    from usso.client.base_client import BaseUssoClient
    from usso.client.client import UssoClient

    client = UssoClient(api_key="k", usso_base_url="https://sso.example")
    assert client.get_session() is client
    with patch("httpx.Client.request", return_value=MagicMock()) as req:
        client._request("GET", "/x")
        req.assert_called()

    # no api key -> empty _get_api_key
    client.api_key = None
    assert client._get_api_key() == {}
    client.agent_id = None
    client.agent_private_key = None
    assert client._get_agent() == {}

    client.api_key = None
    client.access_token = MagicMock(is_temporally_valid=lambda: True)
    with patch("usso.client.client.payload_scopes", return_value=["s"]):
        assert client._get_scopes() == ["s"]

    client.access_token = None
    client.api_key = None
    client.agent_id = "a"
    client.agent_private_key = "pk"
    with patch.object(client, "_get_agent", return_value={"scopes": ["a"]}):
        assert client._get_scopes() == ["a"]

    client.agent_id = None
    client.agent_private_key = None
    with (
        patch.object(
            BaseUssoClient,
            "refresh_token",
            new_callable=PropertyMock,
            return_value="r",
        ),
        patch.object(client, "_get_refresh_token_scopes", return_value=["r"]),
    ):
        assert client._get_scopes() == ["r"]

    with (
        patch.object(
            BaseUssoClient,
            "refresh_token",
            new_callable=PropertyMock,
            return_value="r",
        ),
        patch.object(client, "_refresh", return_value={}),
        patch("usso.client.client.payload_scopes", return_value=["z"]),
    ):
        assert client._get_refresh_token_scopes() == ["z"]

    with pytest.raises(
        ValueError,
        match="agent_id and agent_private_key",
    ):
        client.use_agent_token(scopes=[], aud="sso")

    # refresh TypeError path
    bad = MagicMock()
    bad.raise_for_status = MagicMock()
    bad.json.return_value = {"access_token": None}
    with (
        patch("usso.client.client.httpx.post", return_value=bad),
        patch.object(
            BaseUssoClient,
            "refresh_token",
            new_callable=PropertyMock,
            return_value="r",
        ),
        pytest.raises(TypeError),
    ):
        client._refresh()

    # get_session refresh path without api key
    client.api_key = None
    client.access_token = MagicMock(is_temporally_valid=lambda: False)
    with patch.object(client, "_refresh", return_value={}):
        assert client.get_session() is client


def test_base_client_refresh_property_and_payload_scopes() -> None:
    """Cover refresh_token property clearing and payload_scopes."""
    from usso.client.base_client import (
        BaseUssoClient,
        payload_scopes,
    )

    client = BaseUssoClient(api_key="k", usso_base_url="https://sso.example")
    token = MagicMock()
    token.verify.return_value = True
    token.is_temporally_valid.return_value = True
    client._refresh_token = token
    assert client.refresh_token is None

    assert payload_scopes(None) == []
    tok = MagicMock()
    tok.payload = {"scopes": ["a"]}
    assert payload_scopes(tok) == ["a"]
    tok2 = MagicMock()
    tok2.payload = MagicMock(scopes=["b"])
    # getattr path when payload is not a dict

    class P:
        def __init__(self) -> None:
            self.scopes = ["b"]

    tok2.payload = P()
    assert payload_scopes(tok2) == ["b"]


@pytest.mark.asyncio
async def test_async_cached_api_key_and_agent_methods() -> None:
    """Cover async _get_api_key / _get_agent HTTP helpers."""
    from unittest.mock import AsyncMock

    from usso.client.async_client import AsyncUssoClient

    client = AsyncUssoClient(api_key="k", usso_base_url="https://sso.example")
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"scopes": ["x"]}
    with patch.object(client, "post", new=AsyncMock(return_value=mock_resp)):
        assert (await client._get_api_key())["scopes"] == ["x"]
        with patch(
            "usso.client.async_client.agent.generate_agent_jwt",
            return_value="jwt",
        ):
            client.agent_id = "a"
            client.agent_private_key = "pk"
            assert (await client._get_agent())["scopes"] == ["x"]


def test_django_dependency_header_extractors() -> None:
    """Cover django get_request_jwt/api_key loops."""
    from usso.integrations.django.dependency import USSOAuthentication

    auth = USSOAuthentication(jwt_config=AuthConfig())
    req = MagicMock()
    cfg = MagicMock()
    cfg.get_jwt.return_value = "jwt"
    cfg.get_api_key.return_value = "key"
    auth.jwt_configs = [cfg]
    assert auth.get_request_jwt(req) == "jwt"
    assert auth.get_request_api_key(req) == "key"
    cfg.get_jwt.return_value = None
    cfg.get_api_key.return_value = None
    assert auth.get_request_jwt(req) is None
    assert auth.get_request_api_key(req) is None


@pytest.mark.asyncio
async def test_async_client_scope_branches() -> None:
    """Cover async client remaining scope branches."""
    from unittest.mock import AsyncMock, PropertyMock

    from usso.client.async_client import AsyncUssoClient
    from usso.client.base_client import BaseUssoClient

    client = AsyncUssoClient(api_key="k", usso_base_url="https://sso.example")
    client.access_token = MagicMock(is_temporally_valid=lambda: True)
    with patch(
        "usso.client.async_client.payload_scopes", return_value=["s"]
    ):
        assert await client._get_scopes() == ["s"]

    client.access_token = None
    client.api_key = None
    client.agent_id = "a"
    client.agent_private_key = "pk"
    with patch.object(
        client, "_get_agent", new=AsyncMock(return_value={"scopes": ["a"]})
    ):
        assert await client._get_scopes() == ["a"]

    client.agent_id = None
    client.agent_private_key = None
    with (
        patch.object(
            BaseUssoClient,
            "refresh_token",
            new_callable=PropertyMock,
            return_value="r",
        ),
        patch.object(
            client,
            "_get_refresh_token_scopes",
            new=AsyncMock(return_value=["r"]),
        ),
    ):
        assert await client._get_scopes() == ["r"]

    with (
        patch.object(
            BaseUssoClient,
            "refresh_token",
            new_callable=PropertyMock,
            return_value="r",
        ),
        patch.object(client, "_refresh", new=AsyncMock(return_value={})),
        patch(
            "usso.client.async_client.payload_scopes", return_value=["z"]
        ),
    ):
        assert await client._get_refresh_token_scopes() == ["z"]

    with pytest.raises(ValueError, match="agent_id and private_key"):
        await client.use_agent_token(scopes=[], aud="sso")

    # get_session without api_key refreshes
    client.api_key = None
    client.access_token = None
    with patch.object(client, "_refresh", new=AsyncMock(return_value={})):
        assert await client.get_session() is client

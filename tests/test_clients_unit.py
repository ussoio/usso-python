"""Client unit tests with mocked HTTP."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from usso_jwt.algorithms import EdDSAKey
from usso_jwt.sign import generate_jwt

from usso.client.async_client import AsyncUssoClient
from usso.client.base_client import (
    BaseUssoClient,
    jwt_from_token,
    payload_scopes,
)
from usso.client.client import (
    UssoClient,
    _fetch_agent_scopes,
    _verify_api_key,
)
from usso.enums import AuthIdentifier
from usso.exceptions import PermissionDenied


def test_base_client_requires_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Base client validates auth credentials."""
    for key in (
        "USSO_API_KEY",
        "USSO_REFRESH_TOKEN",
        "AGENT_ID",
        "AGENT_PRIVATE_KEY",
    ):
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(
        ValueError,
        match="one of api_key, refresh_token",
    ):
        BaseUssoClient(usso_base_url="https://sso.example")


def test_base_client_api_key_and_copy() -> None:
    """API key headers and attribute copy."""
    client = BaseUssoClient(
        api_key="k",
        usso_base_url="https://sso.example/",
    )
    assert client.usso_base_url == "https://sso.example"
    assert client.headers_map()["x-api-key"] == "k"
    clone = BaseUssoClient(client=client, api_key="ignored")
    assert clone.api_key == "k"
    assert clone.headers_map()["x-api-key"] == "k"
    assert payload_scopes(None) == []


def test_usso_client_get_users_create_profile_identifier() -> None:
    """Sync client CRUD helpers."""
    client = UssoClient(api_key="k", usso_base_url="https://sso.example")
    now = datetime.now(tz=UTC).isoformat()
    user_json = {
        "uid": "u1",
        "created_at": now,
        "updated_at": now,
        "is_deleted": False,
        "tenant_id": "t",
        "roles": [],
    }

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"items": [user_json]}
    with patch.object(client, "get", return_value=mock_resp):
        users = client.get_users(params={"q": "a"})
        assert users[0].uid == "u1"

    mock_resp.json.return_value = user_json
    with patch.object(client, "post", return_value=mock_resp):
        created = client.create_users({"name": "x"})
        assert created.uid == "u1"

    mock_resp.json.return_value = {"id": "p"}
    with patch.object(client, "get", return_value=mock_resp):
        assert client.get_profile("u1")["id"] == "p"

    with patch.object(client, "post", return_value=mock_resp) as post:
        client.add_identifier("u1", AuthIdentifier.EMAIL, "a@b.co")
        post.assert_called()


def test_usso_client_scopes_and_token() -> None:
    """Scope resolution and permission checks."""
    client = UssoClient(api_key="k", usso_base_url="https://sso.example")
    scopes = {"scopes": ["read:files"]}
    with patch.object(client, "_get_api_key", return_value=scopes):
        assert client._get_scopes() == ["read:files"]
        assert client._get_token("read:files") is None
        with pytest.raises(PermissionDenied):
            client._get_token("admin:*")


def test_usso_client_refresh_and_agent() -> None:
    """Exercise refresh token flow and agent token usage."""
    from unittest.mock import PropertyMock

    key = EdDSAKey.generate()
    now = time_now()
    access = generate_jwt(
        header={"alg": key.algorithm, "typ": "JWT"},
        payload={
            "sub": "u",
            "token_type": "access",
            "scopes": ["read:files"],
            "iat": now - 10,
            "exp": now + 600,
            "nbf": now - 10,
        },
        key=key.private_der(),
        alg=key.algorithm,
    )

    client = UssoClient(api_key="k", usso_base_url="https://sso.example")
    refresh_resp = MagicMock()
    refresh_resp.raise_for_status = MagicMock()
    refresh_resp.json.return_value = {"access_token": access}
    refresh_value = "".join(("refresh", "-", "token"))
    with (
        patch("httpx.post", return_value=refresh_resp),
        patch.object(
            BaseUssoClient,
            "refresh_token",
            new_callable=PropertyMock,
            return_value=refresh_value,
        ),
        patch(
            "usso.client.client.jwt_from_token",
            return_value=MagicMock(),
        ),
    ):
        data = client._refresh()
        assert data["access_token"] == access

    agent_client = UssoClient(
        api_key="k",
        agent_id="agent",
        agent_private_key=key.private_pem().decode(),
        usso_base_url="https://sso.example",
    )
    with (
        patch.object(
            agent_client,
            "_get_agent",
            return_value={"tenant_id": "t", "scopes": ["read:files"]},
        ),
        patch(
            "usso.client.client.agent.get_agent_token",
            return_value=access,
        ),
        patch(
            "usso.client.client.agent.generate_agent_jwt",
            return_value="agent-jwt",
        ),
        patch(
            "usso.client.client.jwt_from_token",
            return_value=MagicMock(is_temporally_valid=lambda: True),
        ),
    ):
        token = agent_client.use_agent_token(scopes=["read:files"], aud="sso")
        assert token == access
        agent_client.access_token = MagicMock(
            is_temporally_valid=lambda: True,
            payload={"scopes": ["read:files"]},
        )
        # payload_scopes path via _get_scopes
        with patch(
            "usso.client.client.payload_scopes",
            return_value=["read:files"],
        ):
            assert agent_client._get_token(["read:files"]) == access


def test_cached_api_key_and_agent_helpers() -> None:
    """Module-level cached helpers."""
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"scopes": ["read:x"]}
    with patch("usso.client.client.httpx.post", return_value=mock_resp):
        _verify_api_key.cache_clear()
        assert _verify_api_key("https://sso.example", "k")["scopes"] == [
            "read:x"
        ]
        _fetch_agent_scopes.cache_clear()
        with patch(
            "usso.client.client.agent.generate_agent_jwt",
            return_value="jwt",
        ):
            assert _fetch_agent_scopes("https://sso.example", "agent", "pk")[
                "scopes"
            ] == ["read:x"]


def time_now() -> int:
    """Return current unix time."""
    import time

    return int(time.time())


@pytest.mark.asyncio
async def test_async_client_basic() -> None:
    """Async client get_users / create_users / scopes."""
    client = AsyncUssoClient(api_key="k", usso_base_url="https://sso.example")
    now = datetime.now(tz=UTC).isoformat()
    user_json = {
        "uid": "u1",
        "created_at": now,
        "updated_at": now,
        "is_deleted": False,
        "tenant_id": "t",
        "roles": [],
    }
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"items": [user_json]}

    with patch.object(client, "get", new=AsyncMock(return_value=mock_resp)):
        users = await client.get_users()
        assert users[0].uid == "u1"

    mock_resp.json.return_value = user_json
    with patch.object(client, "post", new=AsyncMock(return_value=mock_resp)):
        created = await client.create_users({})
        assert created.uid == "u1"

    with patch.object(
        client, "_get_api_key", new=AsyncMock(return_value={"scopes": ["a"]})
    ):
        assert await client._get_scopes() == ["a"]
        assert await client._get_token("a") is None

    session = await client.get_session()
    assert session is client


@pytest.mark.asyncio
async def test_async_client_refresh_and_agent() -> None:
    """Async refresh handling and agent token."""
    from unittest.mock import PropertyMock

    client = AsyncUssoClient(api_key="k", usso_base_url="https://sso.example")
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {
        "access_token": "aaa.bbb.ccc",
        "token": {"refresh_token": "rrr.eee.fff"},
    }
    with patch(
        "usso.client.async_client.jwt_from_token",
        return_value=MagicMock(),
    ):
        data = client._handle_refresh_response(mock_resp)
        assert "access_token" in data

    refresh_value = "".join(("refresh", "-", "token"))
    with (
        patch("httpx.post", return_value=mock_resp),
        patch.object(
            BaseUssoClient,
            "refresh_token",
            new_callable=PropertyMock,
            return_value=refresh_value,
        ),
        patch(
            "usso.client.async_client.jwt_from_token",
            return_value=MagicMock(),
        ),
    ):
        assert "access_token" in client._refresh_sync()

    with (
        patch.object(client, "post", new=AsyncMock(return_value=mock_resp)),
        patch.object(
            BaseUssoClient,
            "refresh_token",
            new_callable=PropertyMock,
            return_value=refresh_value,
        ),
        patch(
            "usso.client.async_client.jwt_from_token",
            return_value=MagicMock(),
        ),
    ):
        assert "access_token" in await client._refresh()

    key = EdDSAKey.generate()
    agent_client = AsyncUssoClient(
        api_key="k",
        agent_id="agent",
        agent_private_key=key.private_pem().decode(),
        usso_base_url="https://sso.example",
    )
    access_value = "".join(("access", ".", "value"))
    with (
        patch.object(
            agent_client,
            "_get_agent",
            new=AsyncMock(
                return_value={"tenant_id": "t", "scopes": ["read:files"]}
            ),
        ),
        patch(
            "usso.client.async_client.agent.get_agent_token_async",
            new=AsyncMock(return_value=access_value),
        ),
        patch(
            "usso.client.async_client.agent.generate_agent_jwt",
            return_value="agent-jwt",
        ),
        patch(
            "usso.client.async_client.jwt_from_token",
            return_value=MagicMock(),
        ),
        patch(
            "usso.client.async_client.payload_scopes",
            return_value=["read:files"],
        ),
    ):
        got = await agent_client.use_agent_token(
            scopes=["read:files"], aud="sso"
        )
        assert got == access_value
        agent_client.access_token = MagicMock(is_temporally_valid=lambda: True)
        assert await agent_client._get_token(["read:files"]) == got

    with patch.object(
        client, "request", new=AsyncMock(return_value=mock_resp)
    ):
        resp = await client._request("GET", "/x")
        assert resp is mock_resp


def test_jwt_from_token_helper() -> None:
    """jwt_from_token builds a JWT wrapper."""
    jwt = jwt_from_token("https://sso.example", "a.b.c")
    assert jwt is not None

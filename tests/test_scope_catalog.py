"""Tests for scope catalog client helpers."""

from types import SimpleNamespace
from unittest import mock

import pytest

from usso.scope_catalog import (
    register_scope_catalog,
    scopes_from_resource_paths,
    scopes_from_routers,
)


def test_scopes_from_resource_paths_builds_action_scopes() -> None:
    """Each resource path expands to action:path scopes."""
    scopes = scopes_from_resource_paths(
        ["file/media/files", "file/media/s3_access_keys"],
        actions=("read", "manage"),
    )
    assert {item["scope"] for item in scopes} == {
        "read:file/media/files",
        "manage:file/media/files",
        "read:file/media/s3_access_keys",
        "manage:file/media/s3_access_keys",
    }


def test_scopes_from_resource_paths_applies_labels() -> None:
    """Optional labels attach by full scope or resource path."""
    scopes = scopes_from_resource_paths(
        ["file/media/files"],
        actions=("manage",),
        labels={
            "file/media/files": {
                "label": "Manage files",
                "label_fa": "files-fa",
            }
        },
    )
    assert scopes == [
        {
            "scope": "manage:file/media/files",
            "label": "Manage files",
            "label_fa": "files-fa",
        }
    ]


def test_scopes_from_routers_reads_resource_path() -> None:
    """Routers expose resource_path like fastapi-mongo-base USSO routers."""
    routers = [
        SimpleNamespace(resource_path="file/media/files"),
        SimpleNamespace(resource_path="file/media/s3_access_keys"),
    ]
    scopes = scopes_from_routers(routers, actions=("read",))
    assert [item["scope"] for item in scopes] == [
        "read:file/media/files",
        "read:file/media/s3_access_keys",
    ]


@pytest.mark.asyncio
async def test_register_scope_catalog_skips_without_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing credentials skip the push without calling HTTP."""
    monkeypatch.delenv("SCOPE_CATALOG_CLIENT_ID", raising=False)
    monkeypatch.delenv("SCOPE_CATALOG_CLIENT_SECRET", raising=False)
    with mock.patch("usso.scope_catalog.httpx.AsyncClient") as client_cls:
        ok = await register_scope_catalog(
            service="media",
            scopes=[{"scope": "read:file/media/files"}],
            usso_base_url="https://sso.example.test",
            enabled=True,
        )
    assert ok is False
    client_cls.assert_not_called()


@pytest.mark.asyncio
async def test_register_scope_catalog_puts_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Successful registration exchanges credentials then PUTs scopes."""
    token_response = mock.MagicMock()
    token_response.raise_for_status = mock.MagicMock()
    token_response.json.return_value = {"access_token": "tok"}

    put_response = mock.MagicMock()
    put_response.raise_for_status = mock.MagicMock()

    client = mock.AsyncMock()
    client.post.return_value = token_response
    client.put.return_value = put_response
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None

    with mock.patch(
        "usso.scope_catalog.httpx.AsyncClient", return_value=client
    ):
        ok = await register_scope_catalog(
            service="media",
            scopes=[{"scope": "manage:file/media/files"}],
            usso_base_url="https://sso.example.test",
            client_id="cid",
            client_secret="secret",  # ruff:ignore[hardcoded-password-func-arg]
            enabled=True,
        )

    assert ok is True
    assert client.post.await_count == 1
    assert client.put.await_count == 1
    put_call = client.put.await_args
    assert put_call.args[0].endswith("/api/sso/v1/scope-catalog/media")
    assert put_call.kwargs["headers"]["Authorization"] == "Bearer tok"
    assert put_call.kwargs["json"] == {
        "scopes": [{"scope": "manage:file/media/files"}]
    }

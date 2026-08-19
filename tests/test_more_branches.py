"""Coverage tests for additional branches across modules."""

import os
from typing import Any

import httpx
import pytest
from httpx import MockTransport
from usso_jwt.algorithms import AbstractKey, EdDSAKey
from usso_jwt.config import JWTConfig
from usso_jwt.schemas import JWT

from src.usso import UserData
from src.usso.client import AsyncUssoClient, UssoClient
from src.usso.exceptions import PermissionDenied
from src.usso.lite import LiteAuth, LiteConfig
from src.usso.lite.database import (
    _secure_sqlite_file,
    configure,
    dispose,
    init_db,
)
from src.usso.utils import validators as main_validators


def _response(json_data: dict) -> httpx.Response:
    return httpx.Response(
        200, json=json_data, request=httpx.Request("POST", "http://test.local")
    )


def _make_client(**kwargs: Any) -> UssoClient:
    kwargs.setdefault("api_key", "test-key")
    return UssoClient(
        transport=MockTransport(lambda request: _response({})),
        **kwargs,
    )


def _signed_token() -> tuple[str, AbstractKey]:
    from usso_jwt import sign

    key = EdDSAKey.generate()
    import time

    now = int(time.time())
    token = sign.generate_jwt(
        header={"alg": "EdDSA", "typ": "JWT"},
        payload={"sub": "u1", "exp": now + 600, "iat": now},
        key=key.private_der(),
        alg="EdDSA",
    )
    return token, key


def test_client_requires_credentials() -> None:
    """UssoClient raises without any authentication credentials."""
    with pytest.raises(ValueError):
        UssoClient(api_key=None, refresh_token=None, agent_id=None)


def test_access_token_scopes_empty() -> None:
    """_access_token_scopes returns an empty list without a token."""
    client = _make_client()
    assert client._access_token_scopes() == []
    client.close()


def test_access_token_scopes_from_userdata() -> None:
    """_access_token_scopes reads scopes from a UserData payload."""
    client = _make_client()
    token, key = _signed_token()
    client.access_token = JWT(
        token=token,
        config=JWTConfig(key=key.jwk()),
        payload_class=UserData,
    )
    assert client._access_token_scopes() == []
    client.close()


def test_get_token_string_scopes_permission_denied() -> None:
    """_get_token with string scopes raises for missing permissions."""
    client = _make_client()  # api_key client, no scopes configured
    with pytest.raises(PermissionDenied):
        client._get_token(scopes="read:users")
    client.close()


async def test_async_get_token_string_scopes_permission_denied() -> None:
    """Async _get_token with string scopes raises for missing permissions."""
    client = AsyncUssoClient(
        transport=MockTransport(lambda request: _response({})),
        api_key="test-key",
    )
    with pytest.raises(PermissionDenied):
        await client._get_token(scopes="read:users")
    await client.aclose()


async def test_async_refresh_sync_without_token() -> None:
    """Async _refresh_sync raises without a refresh token."""
    client = AsyncUssoClient(
        transport=MockTransport(lambda request: _response({})),
        api_key="test-key",
    )
    with pytest.raises(ValueError):
        client._refresh_sync()
    await client.aclose()


def test_secure_sqlite_file_existing(tmp_path: object) -> None:
    """_secure_sqlite_file adjusts permissions on an existing file."""
    path = os.path.join(str(tmp_path), "db.sqlite")
    _secure_sqlite_file(f"sqlite+aiosqlite:///{path}")
    _secure_sqlite_file(f"sqlite+aiosqlite:///{path}")
    assert os.path.exists(path)


def test_validate_username_empty_bad_word() -> None:
    """validate_username tolerates an empty entry in the bad word list."""
    ok, _error, canonical = main_validators.validate_username(
        "goodname", bad_words=["", "nasty"]
    )
    assert ok is True
    assert canonical == "goodname"


def test_lite_dump_missing_attribute() -> None:
    """BaseEntity.dump skips fields that are not attributes."""
    from src.usso.lite.base import BaseEntity

    class _Demo(BaseEntity):
        __abstract__ = True

    entity = _Demo()
    entity.uid = "u1"
    dumped = entity.dump(include_fields=["uid", "missing_attr"])
    assert dumped == {"uid": "u1"}
    assert "missing_attr" not in dumped


async def test_lite_database_dispose() -> None:
    """LiteDatabase.dispose releases the engine cleanly."""
    await dispose()
    cfg = LiteConfig(database_url="sqlite+aiosqlite:///:memory:")
    LiteAuth(cfg)
    configure(cfg.database_url)
    await init_db()
    await dispose()


def test_signing_key_persists_to_file(tmp_path: object) -> None:
    """LiteAuth persists an auto-generated key next to the database."""
    db_path = os.path.join(str(tmp_path), "app.db")
    cfg = LiteConfig(database_url=f"sqlite+aiosqlite:///{db_path}")
    first = LiteAuth(cfg)
    key_file = f"{db_path}.signing.pem"
    assert os.path.exists(key_file)
    second = LiteAuth(cfg)
    assert first.access_key.kid == second.access_key.kid


def test_authorize_denies_when_unauthenticated() -> None:
    """The authorize dependency rejects requests without a valid token."""
    from starlette.requests import Request

    from src.usso.config import APIHeaderConfig, AuthConfig
    from src.usso.integrations.fastapi import USSOAuthentication

    auth = USSOAuthentication(
        jwt_config=AuthConfig(
            key={"kty": "oct", "k": "c2VjcmV0"},
            api_key_header=APIHeaderConfig(),
        )
    )
    auth.raise_exception = False
    authorize = auth.authorize(action="read", resource_path="users")

    scope: dict[str, object] = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }
    request = Request(scope)
    with pytest.raises(RuntimeError):
        authorize(request)

"""Coverage tests for USSO Lite internals (validators, base, database)."""

import os
from typing import Any, cast

import pytest

from src.usso.enums import AuthIdentifier
from src.usso.exceptions import USSOException
from src.usso.lite import (
    LiteAuth,
    LiteConfig,
    dependency,
    validators,
)
from src.usso.lite.base import BaseEntity
from src.usso.lite.database import _secure_sqlite_file


def test_lite_validators_email_errors() -> None:
    """Lite validate_email rejects oversized and malformed emails."""
    assert validators.validate_email("a@" * 128) == (
        False,
        "Email is invalid",
        "",
    )
    assert validators.validate_email("a..b@example.com") == (
        False,
        "Email is invalid",
        "",
    )


def test_lite_validators_phone_errors() -> None:
    """Lite validate_phone strips separators and rejects bad numbers."""
    ok, _error, canonical = validators.validate_phone("+98 912 123")
    assert ok is True
    assert canonical == "+98912123"
    assert validators.validate_phone("abc") == (
        False,
        "Invalid phone number",
        "",
    )


def test_lite_validators_username_errors() -> None:
    """Lite validate_username rejects invalid and reserved names."""
    assert validators.validate_username("ab") == (
        False,
        "Username is invalid",
        "",
    )
    assert validators.validate_username("admin") == (
        False,
        "This username is reserved",
        "",
    )


def test_lite_validators_canonicalize_errors() -> None:
    """Lite canonicalize_identifier raises for unsupported or invalid input."""
    with pytest.raises(ValueError):
        validators.canonicalize_identifier(AuthIdentifier.TELEGRAM_ID, "12345")
    with pytest.raises(ValueError):
        validators.canonicalize_identifier(AuthIdentifier.EMAIL, "bad")


def test_lite_validators_infer_identifier() -> None:
    """Lite infer_identifier_type detects each supported type."""
    assert validators.infer_identifier_type("a@b.com") == AuthIdentifier.EMAIL
    assert (
        validators.infer_identifier_type("+989121234567")
        == AuthIdentifier.PHONE
    )
    assert validators.infer_identifier_type("mahdi") == AuthIdentifier.USERNAME
    with pytest.raises(ValueError):
        validators.infer_identifier_type("???")


def test_base_entity_dump_repr_hash() -> None:
    """BaseEntity dump, repr and hash behave as expected."""

    class _Demo(BaseEntity):
        __abstract__ = True
        name: str

    entity = _Demo()
    entity.uid = "demo-uid"
    entity.name = "test"
    dumped = entity.dump()
    assert "name" in dumped
    assert repr(entity) == "<_Demo uid=demo-uid>"
    assert isinstance(hash(entity), int)


def test_secure_sqlite_file_skips_non_sqlite() -> None:
    """_secure_sqlite_file ignores non-sqlite URLs."""
    _secure_sqlite_file("postgresql://db/host")


def test_secure_sqlite_file_skips_memory() -> None:
    """_secure_sqlite_file ignores in-memory and file: URLs."""
    _secure_sqlite_file("sqlite+aiosqlite:///:memory:")
    _secure_sqlite_file("sqlite+aiosqlite:///file:memdb1?mode=memory")


def test_secure_sqlite_file_creates_private(tmp_path: object) -> None:
    """_secure_sqlite_file creates a new database with private permissions."""
    path = os.path.join(str(tmp_path), "db.sqlite")
    _secure_sqlite_file(f"sqlite+aiosqlite:///{path}")
    assert os.path.exists(path)
    assert os.stat(path).st_mode & 0o777 == 0o600


def test_secure_sqlite_file_rejects_directory(tmp_path: object) -> None:
    """_secure_sqlite_file rejects a non-regular database path."""
    path = str(tmp_path)
    with pytest.raises(RuntimeError):
        _secure_sqlite_file(f"sqlite+aiosqlite:///{path}")


def test_get_auth_unconfigured_raises() -> None:
    """get_auth raises before a router is created."""
    saved = dependency._auth
    dependency._auth = None
    try:
        with pytest.raises(RuntimeError):
            dependency.get_auth()
    finally:
        dependency._auth = saved


def test_extract_access_token_from_bearer() -> None:
    """extract_access_token parses the Authorization header."""
    from starlette.requests import Request

    scope: dict[str, object] = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [
            (b"authorization", b"Bearer abc.def.ghi"),
        ],
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
    }
    request = Request(scope)
    assert dependency.extract_access_token(request) == "abc.def.ghi"


async def test_resolve_current_user_no_token() -> None:
    """resolve_current_user rejects requests without a token."""
    from starlette.requests import Request

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
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
    }
    request = Request(scope)
    auth = LiteAuth(LiteConfig(database_url="sqlite+aiosqlite:///:memory:"))
    with pytest.raises(USSOException) as exc_info:
        await dependency.resolve_current_user(request, cast(Any, None), auth)
    assert exc_info.value.status_code == 401

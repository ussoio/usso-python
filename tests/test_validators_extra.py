"""Coverage tests for validators, agent utilities, and misc helpers."""

import sys

import pytest
from usso_jwt.algorithms import AbstractKey

from src.usso.enums import AuthIdentifier
from src.usso.utils import validators


def test_validate_phone_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """validate_phone falls back to regex when phonenumbers is unavailable."""
    monkeypatch.setitem(sys.modules, "phonenumbers", None)
    ok, error, canonical = validators.validate_phone("+989121234567")
    assert ok is True
    assert error is None
    assert canonical == "+989121234567"

    ok, error, canonical = validators.validate_phone("not-a-number")
    assert ok is False
    assert error is not None
    assert canonical is None


def test_validate_email_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """validate_email falls back to regex when email-validator is missing."""
    monkeypatch.setitem(sys.modules, "email_validator", None)
    ok, error, canonical = validators.validate_email("Ali@Example.com")
    assert ok is True
    assert canonical == "ali@example.com"

    ok, error, canonical = validators.validate_email("not-an-email")
    assert ok is False
    assert error is not None
    assert canonical is None


def test_validate_email_without_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """validate_email skips deliverability when dnspython is unavailable."""
    monkeypatch.setitem(sys.modules, "dns", None)
    ok, _error, canonical = validators.validate_email("dev@usso.io")
    assert ok is True
    assert canonical == "dev@usso.io"


def test_validate_phone_invalid_cases() -> None:
    """validate_phone rejects invalid numbers and wrong country codes."""
    ok, error, canonical = validators.validate_phone("123")
    assert ok is False
    assert error is not None
    assert canonical is None

    ok, error, canonical = validators.validate_phone("+989121234567", "US")
    assert ok is False
    assert error is not None


def test_validate_email_rejects_invalid() -> None:
    """validate_email rejects malformed addresses."""
    ok, error, canonical = validators.validate_email("bad@")
    assert ok is False
    assert error is not None
    assert canonical is None


def test_validate_username_bad_word() -> None:
    """validate_username rejects disallowed language."""
    ok, error, _canonical = validators.validate_username("fuckyouser")
    assert ok is False
    assert error is not None


def test_validate_username_reserved() -> None:
    """validate_username rejects reserved names."""
    ok, error, _canonical = validators.validate_username("admin")
    assert ok is False
    assert error is not None


def test_validate_username_valid() -> None:
    """validate_username accepts a canonical username."""
    ok, _error, canonical = validators.validate_username("Mahdi_Kiani")
    assert ok is True
    assert canonical == "mahdi_kiani"


def test_determine_identifier_type_from_fields() -> None:
    """determine_identifier_type reads phone, email and username fields."""
    identifier_type, value = validators.determine_identifier_type({
        "phone": "+989121234567"
    })
    assert identifier_type == AuthIdentifier.PHONE
    assert value == "+989121234567"

    identifier_type, value = validators.determine_identifier_type({
        "email": "a@b.com"
    })
    assert identifier_type == AuthIdentifier.EMAIL
    assert value == "a@b.com"

    identifier_type, value = validators.determine_identifier_type({
        "username": "mahdi"
    })
    assert identifier_type == AuthIdentifier.USERNAME
    assert value == "mahdi"


def test_determine_identifier_type_from_sub() -> None:
    """determine_identifier_type validates the sub field when present."""
    identifier_type, value = validators.determine_identifier_type({
        "sub": "+989121234567"
    })
    assert identifier_type == AuthIdentifier.PHONE

    identifier_type, value = validators.determine_identifier_type({})
    assert identifier_type is None
    assert value is None


def test_canonicalize_identifier() -> None:
    """canonicalize_identifier normalizes identifiers by type."""
    assert (
        validators.canonicalize_identifier(
            AuthIdentifier.EMAIL, "ali@Example.com"
        )
        == "ali@example.com"
    )
    assert (
        validators.canonicalize_identifier(AuthIdentifier.USERNAME, "MAHDI")
        == "mahdi"
    )
    assert (
        validators.canonicalize_identifier(
            AuthIdentifier.PHONE, "+989121234567"
        )
        == "989121234567"
    )
    assert (
        validators.canonicalize_identifier(
            AuthIdentifier.TELEGRAM_ID, "123456"
        )
        == "123456"
    )
    with pytest.raises(ValueError):
        validators.canonicalize_identifier(AuthIdentifier.EMAIL, "bad")


def test_infer_identifier_type() -> None:
    """infer_identifier_type detects the identifier kind."""
    assert (
        validators.infer_identifier_type("ali@example.com")
        == AuthIdentifier.EMAIL
    )
    assert (
        validators.infer_identifier_type("+989121234567")
        == AuthIdentifier.PHONE
    )
    assert (
        validators.infer_identifier_type("mahdi_kiani")
        == AuthIdentifier.USERNAME
    )
    with pytest.raises(ValueError):
        validators.infer_identifier_type("???!!!")


def test_generate_agent_jwt_bytes_key(
    test_key: AbstractKey,
) -> None:
    """generate_agent_jwt accepts a raw bytes private key."""
    from usso_jwt.schemas import UnverifiedJWT

    from src.usso.utils.agent import generate_agent_jwt

    der = test_key.private_der()
    jwt = generate_agent_jwt(
        scopes=["read:users"],
        aud="https://usso.uln.me",
        agent_id="agent-1",
        private_key=der,
    )
    parsed = UnverifiedJWT(token=jwt)
    assert len(jwt.split(".")) == 3
    assert parsed.unverified_header["kid"] == test_key.kid


def test_get_authorization_scheme_param_none() -> None:
    """get_authorization_scheme_param handles a missing header."""
    from src.usso.utils.string_utils import get_authorization_scheme_param

    assert get_authorization_scheme_param(None) == ("", "")


def test_exception_handler_generic() -> None:
    """The exception handler converts non-USSO exceptions to a 500."""
    from fastapi.responses import JSONResponse
    from starlette.requests import Request

    from src.usso.integrations.fastapi.handler import usso_exception_handler

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
    response = usso_exception_handler(request, ValueError("boom"))
    assert isinstance(response, JSONResponse)
    assert response.status_code == 500

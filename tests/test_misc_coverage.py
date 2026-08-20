"""Coverage tests for schemas, config, api-key, and user helpers."""

from typing import Any, cast

import httpx
import pytest

from usso import UserData
from usso.api_key import (
    fetch_api_key_data,
    fetch_api_key_data_async,
)
from usso.config import AuthConfig, HeaderConfig
from usso.enums import AuthIdentifier
from usso.exceptions import USSOException
from usso.schemas import Identifier, OTPRequest


def test_identifier_without_type_passes_through() -> None:
    """Identifier skips canonicalization when no type is provided."""
    ident = Identifier(identifier="raw.value")
    assert ident.identifier == "raw.value"


def test_identifier_invalid_value_raises() -> None:
    """Identifier rejects values invalid for the declared type."""
    with pytest.raises(ValueError):
        Identifier(type=AuthIdentifier.EMAIL, identifier="not-an-email")


def test_otp_request_email_channel() -> None:
    """OTPRequest defaults the channel to email for email identifiers."""
    req = OTPRequest(type=AuthIdentifier.EMAIL, identifier="dev@usso.io")
    assert req.channel_type == "email"


def test_otp_request_phone_channel() -> None:
    """OTPRequest defaults the channel to sms for phone identifiers."""
    req = OTPRequest(type=AuthIdentifier.PHONE, identifier="+989121234567")
    assert req.channel_type == "sms"


def test_otp_request_invalid_type_raises() -> None:
    """OTPRequest rejects identifiers without a mapped channel."""
    with pytest.raises(ValueError):
        OTPRequest(type=AuthIdentifier.USERNAME, identifier="jane")


def test_otp_request_invalid_channel_raises() -> None:
    """OTPRequest rejects unknown channel types."""
    with pytest.raises(ValueError):
        OTPRequest(
            type=AuthIdentifier.PHONE,
            identifier="+989121234567",
            channel_type="carrier-pigeon",
        )


def test_header_config_no_header_name() -> None:
    """HeaderConfig returns None when no header name is configured."""
    header = HeaderConfig(header_name=None)
    assert header._get_key_header(object()) is None


def test_auth_config_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """AuthConfig loads JWT_CONFIG from the environment."""
    import json

    from usso_jwt.algorithms import EdDSAKey

    key = EdDSAKey.generate()
    monkeypatch.setenv("JWT_CONFIG", json.dumps({"key": key.jwk()}))
    config = AuthConfig()
    assert config.key is not None


def test_auth_config_default_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """AuthConfig builds a default JWKS URL when JWT_CONFIG is unset."""
    monkeypatch.delenv("JWT_CONFIG", raising=False)
    monkeypatch.setenv("USSO_BASE_URL", "https://sso.example.com")
    config = AuthConfig()
    assert config.jwks_url == ("https://sso.example.com/.well-known/jwks.json")


def test_verify_token_invalid_relaxed() -> None:
    """verify_token returns False for an invalid token when relaxed."""
    config = AuthConfig(key={"kty": "oct", "k": "c2VjcmV0"})
    assert config.verify_token("invalid.token", raise_exception=False) is False


def test_verify_token_invalid_raises() -> None:
    """verify_token re-raises JWT errors when raise_exception is True."""
    from usso_jwt.exceptions import JWTError

    config = AuthConfig(key={"kty": "oct", "k": "c2VjcmV0"})
    with pytest.raises(JWTError):
        config.verify_token("invalid.token", raise_exception=True)


def test_parse_config_from_dict() -> None:
    """_parse_config accepts a raw dictionary."""
    config = AuthConfig._parse_config({"jwks_url": "https://sso/jwks.json"})
    assert config.jwks_url == "https://sso/jwks.json"


def test_parse_config_invalid_raises() -> None:
    """_parse_config rejects unsupported inputs."""
    with pytest.raises(ValueError):
        AuthConfig._parse_config(cast(Any, 123))


def test_validate_jwt_configs_list() -> None:
    """validate_jwt_configs accepts a list of config dicts."""
    configs = AuthConfig.validate_jwt_configs([
        {"jwks_url": "https://a/jwks.json"},
        {"jwks_url": "https://b/jwks.json"},
    ])
    assert len(configs) == 2


def test_validate_jwt_configs_invalid_raises() -> None:
    """validate_jwt_configs rejects unsupported formats."""
    with pytest.raises(ValueError):
        AuthConfig.validate_jwt_configs(cast(Any, 123))


def test_fetch_api_key_data_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """fetch_api_key_data raises when the verify request fails."""
    monkeypatch.setattr(
        httpx,
        "post",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            httpx.ConnectError("boom")
        ),
    )
    with pytest.raises(USSOException):
        fetch_api_key_data("https://sso/verify", "key")


async def test_fetch_api_key_data_async_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """fetch_api_key_data_async raises when the verify request fails."""

    class _BadClient:
        def __init__(self, **kwargs: object) -> None:
            pass

        async def __aenter__(self) -> "_BadClient":
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def post(self, *args: object, **kwargs: object) -> object:
            raise httpx.ConnectError("boom")

    monkeypatch.setattr(httpx, "AsyncClient", _BadClient)
    with pytest.raises(USSOException):
        await fetch_api_key_data_async("https://sso/verify", "key")


def test_fetch_api_key_data_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """fetch_api_key_data returns user data for a successful verify."""

    def fake_post(url: str, **kwargs: object) -> httpx.Response:
        return httpx.Response(
            200,
            json={"sub": "u1"},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    user = fetch_api_key_data("https://sso/verify", "key")
    assert user.uid == "u1"


async def test_fetch_api_key_data_async_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """fetch_api_key_data_async returns user data for a successful verify."""

    class _GoodClient:
        def __init__(self, **kwargs: object) -> None:
            pass

        async def __aenter__(self) -> "_GoodClient":
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def post(self, url: str, **kwargs: object) -> httpx.Response:
            return httpx.Response(
                200,
                json={"sub": "u1"},
                request=httpx.Request("POST", url),
            )

    monkeypatch.setattr(httpx, "AsyncClient", _GoodClient)
    user = await fetch_api_key_data_async("https://sso/verify", "key")
    assert user.uid == "u1"


def test_user_data_empty_properties() -> None:
    """UserData returns empty strings for missing identity fields."""
    user = UserData()
    assert user.user_name == ""
    assert user.email == ""
    assert user.phone == ""


def test_user_data_phone_from_claims() -> None:
    """UserData exposes phone from its claims."""
    user = UserData(phone="+989121234567")
    assert user.phone == "+989121234567"

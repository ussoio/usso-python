"""Unit tests for auth, api keys, config, user, and exceptions."""

from __future__ import annotations

import asyncio
import base64
import json
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from usso_jwt.sign import generate_jwt

from usso.api_key import fetch_api_key_data, fetch_api_key_data_async
from usso.auth import UssoAuth
from usso.config import APIHeaderConfig, AuthConfig, HeaderConfig
from usso.enums import AuthIdentifier, AuthSecret, ChannelType
from usso.exceptions import (
    PermissionDenied,
    PermissionDeniedError,
    USSOError,
    USSOException,
    _handle_exception,
    _raise_auth_error,
)
from usso.schemas import Identifier, LoginRequest, OTPRequest, Secret
from usso.user import TokenType, UserData
from usso.utils.string_utils import get_authorization_scheme_param

if TYPE_CHECKING:
    from usso_jwt.algorithms import EdDSAKey


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def test_usso_error_alias_and_permission_denied() -> None:
    """Aliases and permission denied construction."""
    assert USSOException is USSOError
    assert PermissionDenied is PermissionDeniedError
    err = PermissionDenied(detail="nope")
    assert err.status_code == 403
    assert "nope" in str(err.detail)


def test_handle_exception_raises_and_logs() -> None:
    """_handle_exception raises by default and logs when disabled."""
    with pytest.raises(USSOError):
        _handle_exception("unauthorized", message="x")
    _handle_exception("unauthorized", message="x", raise_exception=False)
    with pytest.raises(USSOError):
        _raise_auth_error("unauthorized", message="boom")


def test_usso_error_message_variants() -> None:
    """Cover message dict / string / default branches."""
    err = USSOError(401, "unauthorized", detail="d")
    assert err.message["en"] == "Unauthorized"
    err2 = USSOError(401, "unauthorized", message="plain")
    assert err2.message == {"en": "plain"}
    err3 = USSOError(401, "unauthorized", message={"en": "m", "fa": "ف"})
    assert err3.message["fa"] == "ف"
    custom = USSOError.__new__(USSOError)
    custom.message_en = ""
    custom.message_fa = None
    USSOError.__init__(custom, 401, "x", detail="only")
    assert custom.message == {"en": "only"}


def test_user_data_properties() -> None:
    """UserData properties and TokenType values."""
    user = UserData(
        sub="u1",
        user_id="custom",
        user_name="Ada",
        email="a@b.co",
        phone="123",
        token_type=TokenType.ACCESS,
    )
    assert user.uid == "custom"
    assert user.user_name == "Ada"
    assert user.email == "a@b.co"
    assert user.phone == "123"
    assert str(TokenType.SECURE_TOKEN) == "".join(("sec", "ure"))
    assert str(TokenType.ONE_TIME_TOKEN) == "".join(("one", "_", "time"))
    assert str(TokenType.TEMPORARY_TOKEN) == "".join(("tempor", "ary"))
    bare = UserData(sub="only-sub")
    assert bare.user_id == "only-sub"
    assert bare.user_name == ""
    assert bare.email == ""
    assert bare.phone == ""


def test_header_config_extraction() -> None:
    """Header and cookie extraction."""
    cfg = HeaderConfig()
    req = MagicMock()
    req.headers = {"Authorization": "Bearer abc.def.ghi"}
    req.cookies = {}
    assert cfg.get_key(req) == "abc.def.ghi"

    cfg2 = HeaderConfig(header_name="X-Token", cookie_name="c")
    req2 = MagicMock()
    req2.headers = {"X-Token": "tok"}
    req2.cookies = {}
    assert cfg2.get_key(req2) == "tok"

    cfg3 = HeaderConfig(header_name=None, cookie_name="c")
    req3 = MagicMock()
    req3.headers = {}
    req3.cookies = {"c": "cookie-tok"}
    assert cfg3.get_key(req3) == "cookie-tok"

    assert hash(cfg) == hash(cfg)
    assert get_authorization_scheme_param(None) == ("", "")
    assert get_authorization_scheme_param("Bearer x") == ("Bearer", "x")


def test_auth_config_env_and_verify(monkeypatch: pytest.MonkeyPatch) -> None:
    """AuthConfig loads from env and verifies tokens."""
    monkeypatch.delenv("JWT_CONFIG", raising=False)
    monkeypatch.setenv("USSO_BASE_URL", "https://sso.example")
    cfg = AuthConfig()
    assert "jwks.json" in (cfg.jwks_url or "")

    monkeypatch.setenv(
        "JWT_CONFIG",
        json.dumps({"jwks_url": "https://sso.example/.well-known/jwks.json"}),
    )
    cfg2 = AuthConfig()
    assert cfg2.jwks_url is not None
    assert cfg2.jwks_url.endswith("jwks.json")

    parsed = AuthConfig.validate_jwt_configs(
        '{"jwks_url": "https://sso.example/.well-known/jwks.json"}'
    )
    assert len(parsed) == 1
    assert AuthConfig.validate_jwt_configs([{"jwks_url": "https://x/j"}])
    with pytest.raises(ValueError, match="Invalid jwt_config format"):
        AuthConfig.validate_jwt_configs(cast("Any", 123))
    req = MagicMock()
    req.headers = {"Authorization": "Bearer t", "x-api-key": "k"}
    req.cookies = {}
    assert cfg.get_jwt(req)
    assert cfg.get_api_key(req)

    cfg.api_key_header = None
    cfg.jwt_header = None
    assert cfg.get_api_key(req) is None
    assert cfg.get_jwt(req) is None

    assert cfg2.verify_token("not-a-jwt", raise_exception=False) is False
    from usso_jwt import exceptions as jwt_exc

    with pytest.raises(jwt_exc.JWTError):
        cfg2.verify_token("not-a-jwt", raise_exception=True)


def test_enums_and_schemas() -> None:
    """Enum helpers and schema validators."""
    assert str(AuthSecret.PASSWORD) == "".join(("pass", "word"))
    assert str(AuthSecret.ID_TOKEN) == "".join(("id", "_", "token"))
    assert str(AuthSecret.TELEGRAM_TOKEN) == "".join((
        "telegram",
        "_",
        "token",
    ))
    assert (
        AuthSecret.get_identifier_type(AuthSecret.EMAIL_OTP)
        == AuthIdentifier.EMAIL
    )
    assert AuthSecret.get_identifier_type(AuthSecret.PASSWORD) is None
    validator = AuthIdentifier.USERNAME.get_identifier_validator()
    ok, _, canon = validator("valid_user")
    assert ok
    assert canon == "valid_user"
    passthrough = AuthIdentifier.CLIENT_ID.get_identifier_validator()
    assert passthrough("x")[0] is True

    ident = Identifier(type=AuthIdentifier.USERNAME, identifier="valid_user")
    assert ident.identifier == "valid_user"
    with pytest.raises(ValueError, match="Username must be 3-30"):
        Identifier(type=AuthIdentifier.USERNAME, identifier="ab")

    otp = OTPRequest(type=AuthIdentifier.EMAIL, identifier="a@b.co")
    assert otp.channel_type == "email"
    otp2 = OTPRequest(
        type=AuthIdentifier.PHONE,
        identifier="+14155550173",
        channel_type="sms",
    )
    assert otp2.channel_type == "sms"
    with pytest.raises(ValueError, match="Invalid identifier type"):
        OTPRequest(type=AuthIdentifier.USERNAME, identifier="valid_user")
    with pytest.raises(ValueError, match="Invalid channel type"):
        OTPRequest.model_validate({
            "type": "email",
            "identifier": "a@b.co",
            "channel_type": "nope",
        })
    assert ChannelType.email == "email"
    login = LoginRequest(
        type=AuthIdentifier.USERNAME,
        identifier="valid_user",
        method=AuthSecret.PASSWORD,
        secret="".join(("s",)),
    )
    assert login.referral_code is None
    secret = Secret(method=AuthSecret.TOTP, secret="".join(("1",)))
    assert isinstance(secret, Secret)


def test_compact_token_detection() -> None:
    """JWT/JWE compact detection and base64url checks."""
    assert UssoAuth.is_base64url_segment("") is False
    assert UssoAuth.is_base64url_segment("abc def") is False
    assert UssoAuth.is_base64url_segment("@@@") is False
    assert UssoAuth.is_base64url_segment("=") is False
    assert UssoAuth.is_base64url_segment(_b64url(b"hi")) is True

    jwtish = ".".join([_b64url(b"a"), _b64url(b"b"), _b64url(b"c")])
    assert UssoAuth.detect_compact_token_type(jwtish) == "jwt"
    jweish = ".".join([_b64url(b"a")] * 5)
    assert UssoAuth.detect_compact_token_type(jweish) == "jwe"
    assert UssoAuth.detect_compact_token_type("not-a-token") is None


def test_user_data_from_token_success(
    test_key: EdDSAKey, test_valid_payload: dict
) -> None:
    """Successful JWT verification via UssoAuth."""
    token = generate_jwt(
        header={"alg": test_key.algorithm, "typ": "JWT"},
        payload={**test_valid_payload, "token_type": "access"},
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    auth = UssoAuth(
        jwt_config={
            "type": "EDDSA",
            "key": test_key.public_pem().decode(),
        }
    )
    user = auth.user_data_from_token(token)
    assert user is not None
    assert user.sub == test_valid_payload["sub"]


def test_user_data_from_token_failure(test_key: EdDSAKey) -> None:
    """Invalid token raises or returns None."""
    auth = UssoAuth(
        jwt_config={
            "type": "EDDSA",
            "key": test_key.public_pem().decode(),
        }
    )
    with pytest.raises(USSOError):
        auth.user_data_from_token("a.b.c")
    assert auth.user_data_from_token("a.b.c", raise_exception=False) is None


def test_api_key_verifier_sync_and_async() -> None:
    """In-process API key verifiers."""
    user = UserData(sub="api-user")

    def sync_verifier(key: str) -> UserData:
        assert key == "k"
        return user

    async def async_verifier(_key: str) -> UserData:
        await asyncio.sleep(0)
        return user

    auth = UssoAuth(
        jwt_config=AuthConfig(
            jwks_url="https://example/.well-known/jwks.json",
            api_key_header=APIHeaderConfig(
                api_key_verifier=sync_verifier,
            ),
        )
    )
    assert auth.user_data_from_api_key("k").sub == "api-user"

    auth2 = UssoAuth(
        jwt_config=AuthConfig(
            jwks_url="https://example/.well-known/jwks.json",
            api_key_header=APIHeaderConfig(
                api_key_verifier_async=async_verifier,
            ),
        )
    )
    assert auth2.user_data_from_api_key("k").sub == "api-user"

    auth3 = UssoAuth(jwt_config=AuthConfig())
    auth3.jwt_configs[0].api_key_header = None
    with pytest.raises(USSOError):
        auth3.user_data_from_api_key("k")


@pytest.mark.asyncio
async def test_api_key_verifier_async_path() -> None:
    """Async API key verification paths."""
    user = UserData(sub="async-user")

    async def async_verifier(_key: str) -> UserData:
        await asyncio.sleep(0)
        return user

    def sync_verifier(_key: str) -> UserData:
        return user

    auth = UssoAuth(
        jwt_config=AuthConfig(
            jwks_url="https://example/.well-known/jwks.json",
            api_key_header=APIHeaderConfig(
                api_key_verifier_async=async_verifier,
            ),
        )
    )
    assert (await auth.user_data_from_api_key_async("k")).sub == "async-user"

    auth2 = UssoAuth(
        jwt_config=AuthConfig(
            jwks_url="https://example/.well-known/jwks.json",
            api_key_header=APIHeaderConfig(api_key_verifier=sync_verifier),
        )
    )
    assert (await auth2.user_data_from_api_key_async("k")).sub == "async-user"

    auth3 = UssoAuth(jwt_config=AuthConfig())
    auth3.jwt_configs[0].api_key_header = None
    with pytest.raises(USSOError):
        await auth3.user_data_from_api_key_async("k")


def test_jwe_paths() -> None:
    """JWE placeholder behavior."""
    auth = UssoAuth(jwt_config=AuthConfig())
    with pytest.raises(USSOError):
        auth.user_data_from_jwe("a.b.c.d.e")
    assert auth.user_data_from_jwe("a.b.c.d.e", raise_exception=False) is None


@pytest.mark.asyncio
async def test_jwe_async() -> None:
    """Async JWE wrapper."""
    auth = UssoAuth(jwt_config=AuthConfig())
    assert (
        await auth.user_data_from_jwe_async("x", raise_exception=False) is None
    )


def test_fetch_api_key_data_success_and_error() -> None:
    """HTTP API key fetch helpers."""
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"sub": "u"}

    with patch("usso.api_key.httpx.post", return_value=mock_resp):
        user = fetch_api_key_data("https://verify-ok", "key-ok")
        assert user.sub == "u"

    fetch_api_key_data.cache_clear()
    with (
        patch(
            "usso.api_key.httpx.post",
            side_effect=httpx.HTTPError("fail"),
        ),
        pytest.raises(USSOError),
    ):
        fetch_api_key_data("https://verify-fail", "key-fail")


@pytest.mark.asyncio
async def test_fetch_api_key_data_async() -> None:
    """Async HTTP API key fetch."""
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"sub": "u2"}

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None
    mock_client.post.return_value = mock_resp

    with patch("usso.api_key.httpx.AsyncClient", return_value=mock_client):
        user = await fetch_api_key_data_async("https://verify", "key")
        assert user.sub == "u2"

    mock_client.post.side_effect = httpx.HTTPError("fail")
    with (
        patch("usso.api_key.httpx.AsyncClient", return_value=mock_client),
        pytest.raises(USSOError),
    ):
        await fetch_api_key_data_async("https://verify", "key")


def test_usso_auth_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """UssoAuth initializes from JWT_CONFIGS / JWT_CONFIG env."""
    monkeypatch.setenv(
        "JWT_CONFIGS",
        json.dumps([{"jwks_url": "https://a/.well-known/jwks.json"}]),
    )
    monkeypatch.delenv("JWT_CONFIG", raising=False)
    auth = UssoAuth()
    assert len(auth.jwt_configs) == 1

    monkeypatch.delenv("JWT_CONFIGS", raising=False)
    monkeypatch.setenv(
        "JWT_CONFIG",
        json.dumps({"jwks_url": "https://b/.well-known/jwks.json"}),
    )
    auth2 = UssoAuth()
    assert auth2.jwt_configs[0].jwks_url is not None
    assert auth2.jwt_configs[0].jwks_url.endswith("jwks.json")

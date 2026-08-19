"""Coverage tests for the UssoAuth authentication client."""

import json
import time
from collections.abc import Callable
from typing import Any, cast

import pytest
from usso_jwt import sign
from usso_jwt.algorithms import EdDSAKey
from usso_jwt.schemas import JWT

from src.usso import UssoAuth
from src.usso.auth import _coerce_user_data
from src.usso.config import APIHeaderConfig, AuthConfig
from src.usso.exceptions import USSOException
from src.usso.user import UserData


def _signed_token(**claims: object) -> str:
    """Return a signed EdDSA JWT with the given extra claims."""
    key = EdDSAKey.generate()
    now = int(time.time())
    payload: dict[str, object] = {
        "sub": "u1",
        "exp": now + 600,
        "iat": now,
        **claims,
    }
    return sign.generate_jwt(
        header={"alg": "EdDSA", "typ": "JWT"},
        payload=payload,
        key=key.private_der(),
        alg="EdDSA",
    )


def _make_auth(**config_kwargs: object) -> UssoAuth:
    """Build an UssoAuth with an EdDSA key and optional api key verifier."""
    key = EdDSAKey.generate()
    data: dict[str, object] = {"key": key.jwk(), **config_kwargs}
    return UssoAuth(jwt_config=AuthConfig(**data))


def test_coerce_user_data_dict_and_error() -> None:
    """_coerce_user_data handles dict payloads and rejects others."""
    user = _coerce_user_data({"sub": "u1"})
    assert user.uid == "u1"
    with pytest.raises(TypeError):
        _coerce_user_data(123)


def test_init_reads_jwt_configs_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """__init__ loads a JSON list from JWT_CONFIGS."""
    key = EdDSAKey.generate()
    monkeypatch.setenv(
        "JWT_CONFIGS",
        json.dumps([{"key": key.jwk(), "type": "EDDSA"}]),
    )
    monkeypatch.delenv("JWT_CONFIG", raising=False)
    auth = UssoAuth()
    assert len(auth.jwt_configs) == 1


def test_init_reads_jwt_config_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """__init__ falls back to JWT_CONFIG when JWT_CONFIGS is absent."""
    key = EdDSAKey.generate()
    monkeypatch.delenv("JWT_CONFIGS", raising=False)
    monkeypatch.setenv(
        "JWT_CONFIG",
        json.dumps({"key": key.jwk(), "type": "EDDSA"}),
    )
    auth = UssoAuth()
    assert len(auth.jwt_configs) == 1


def test_init_default_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """__init__ builds a default config from USSO_BASE_URL when unset."""
    monkeypatch.delenv("JWT_CONFIGS", raising=False)
    monkeypatch.delenv("JWT_CONFIG", raising=False)
    monkeypatch.setenv("USSO_BASE_URL", "https://sso.example.com")
    auth = UssoAuth()
    assert auth.from_usso_base_url == "https://sso.example.com"
    assert len(auth.jwt_configs) == 1


def test_is_base64url_segment_padding_only() -> None:
    """is_base64url_segment rejects padding-only segments."""
    assert UssoAuth.is_base64url_segment("=") is False


def test_is_base64url_segment_edge_cases() -> None:
    """is_base64url_segment rejects malformed segments."""
    assert UssoAuth.is_base64url_segment("") is False
    assert UssoAuth.is_base64url_segment("a b") is False
    assert UssoAuth.is_base64url_segment("a!b") is False
    assert UssoAuth.is_base64url_segment("===") is False
    assert UssoAuth.is_base64url_segment("a") is False


def test_user_data_from_token_with_base_url_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """user_data_from_token falls back when base URL verification fails."""
    import usso_jwt.exceptions

    def _raise_jwt(*args: object, **kwargs: object) -> bool:
        raise usso_jwt.exceptions.JWTInvalidFormatError()

    monkeypatch.setattr(JWT, "verify", _raise_jwt)
    auth = _make_auth()
    auth.from_usso_base_url = "https://sso.example.com"
    token = _signed_token(iss="https://issuer.example.com")
    result = auth.user_data_from_token(token, raise_exception=False)
    assert result is None


def test_user_data_from_api_key_not_configured() -> None:
    """user_data_from_api_key raises when API keys are not configured."""
    auth = _make_auth(api_key_header=None)
    with pytest.raises(USSOException):
        auth.user_data_from_api_key("key")


async def test_user_data_from_api_key_async_not_configured() -> None:
    """user_data_from_api_key_async raises when API keys are not configured."""
    auth = _make_auth(api_key_header=None)
    with pytest.raises(USSOException):
        await auth.user_data_from_api_key_async("key")


def test_user_data_from_jwe_raises() -> None:
    """user_data_from_jwe raises by default."""
    auth = _make_auth()
    with pytest.raises(USSOException):
        auth.user_data_from_jwe("a.b.c.d.e")


def test_is_base64url_segment_valid() -> None:
    """is_base64url_segment accepts a valid base64url segment."""
    from usso_jwt.utils import b64url_encode

    segment = b64url_encode(b"header")
    assert UssoAuth.is_base64url_segment(segment) is True


def test_detect_compact_token_types() -> None:
    """detect_compact_token_type classifies JWT, JWE and raw tokens."""
    valid_segment = "eyJhbGciOiJIUzI1NiJ9"
    assert (
        UssoAuth.detect_compact_token_type(".".join([valid_segment] * 3))
        == "jwt"
    )
    assert (
        UssoAuth.detect_compact_token_type(".".join([valid_segment] * 5))
        == "jwe"
    )
    assert UssoAuth.detect_compact_token_type("raw-key") is None


def test_user_data_from_token_with_base_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """user_data_from_token resolves JWKS via from_usso_base_url."""
    monkeypatch.setattr(JWT, "verify", lambda self, **kw: True)
    auth = _make_auth()
    auth.from_usso_base_url = "https://sso.example.com"
    token = _signed_token(iss="https://issuer.example.com")
    user = auth.user_data_from_token(token)
    assert user is not None
    assert user.uid == "u1"


def test_user_data_from_token_returns_none_when_relaxed() -> None:
    """user_data_from_token returns None when raise_exception is False."""
    auth = _make_auth()
    result = auth.user_data_from_token(
        "invalid.token.value", raise_exception=False
    )
    assert result is None


def test_run_sync_api_key_verifier_sync(
    test_key: object,
) -> None:
    """_run_sync_api_key_verifier calls the sync verifier."""
    header = APIHeaderConfig(api_key_verifier=lambda key: UserData(sub=key))
    user = UssoAuth._run_sync_api_key_verifier(header, "k1")
    assert user.uid == "k1"


def test_run_sync_api_key_verifier_async_non_awaitable() -> None:
    """_run_sync_api_key_verifier accepts a non-awaitable async result."""
    from collections.abc import Coroutine

    header = APIHeaderConfig(
        api_key_verifier_async=cast(
            Callable[[str], Coroutine[Any, Any, UserData]],
            lambda key: UserData(sub=key),
        )
    )
    user = UssoAuth._run_sync_api_key_verifier(header, "k1")
    assert user.uid == "k1"


def test_run_sync_api_key_verifier_async_awaitable() -> None:
    """_run_sync_api_key_verifier runs an awaitable outside a loop."""

    async def _verify(key: str) -> UserData:
        return UserData(sub=key)

    header = APIHeaderConfig(api_key_verifier_async=_verify)
    user = UssoAuth._run_sync_api_key_verifier(header, "k1")
    assert user.uid == "k1"


async def test_run_sync_api_key_verifier_awaitable_in_loop() -> None:
    """_run_sync_api_key_verifier raises inside a running loop."""

    async def _verify(key: str) -> UserData:
        return UserData(sub=key)

    header = APIHeaderConfig(api_key_verifier_async=_verify)
    with pytest.raises(RuntimeError):
        UssoAuth._run_sync_api_key_verifier(header, "k1")


def test_run_sync_api_key_verifier_missing() -> None:
    """_run_sync_api_key_verifier raises when no verifier is configured."""
    header = APIHeaderConfig()
    with pytest.raises(RuntimeError):
        UssoAuth._run_sync_api_key_verifier(header, "k1")


def test_user_data_from_api_key_remote(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """user_data_from_api_key uses the remote verify endpoint."""
    import src.usso.auth as auth_module

    monkeypatch.setattr(
        auth_module,
        "fetch_api_key_data",
        lambda url, key: UserData(sub=key),
    )
    auth = _make_auth()
    user = auth.user_data_from_api_key("remote-key")
    assert user.uid == "remote-key"


async def test_user_data_from_api_key_async_verifiers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """user_data_from_api_key_async uses async then sync verifiers."""
    import src.usso.auth as auth_module

    async def _async_verify(key: str) -> UserData:
        return UserData(sub=key)

    sync_auth = _make_auth(
        api_key_header=APIHeaderConfig(
            api_key_verifier=lambda k: UserData(sub=k)
        )
    )
    user = await sync_auth.user_data_from_api_key_async("k1")
    assert user.uid == "k1"

    async_auth = _make_auth(
        api_key_header=APIHeaderConfig(api_key_verifier_async=_async_verify)
    )
    user = await async_auth.user_data_from_api_key_async("k1")
    assert user.uid == "k1"

    async def _fake_fetch_async(url: str, key: str) -> UserData:
        return UserData(sub=key)

    monkeypatch.setattr(
        auth_module,
        "fetch_api_key_data_async",
        _fake_fetch_async,
    )
    remote_auth = _make_auth()
    user = await remote_auth.user_data_from_api_key_async("k1")
    assert user.uid == "k1"


def test_user_data_from_jwe_relaxed() -> None:
    """user_data_from_jwe returns None when raise_exception is False."""
    auth = _make_auth()
    result = auth.user_data_from_jwe("a.b.c.d.e", raise_exception=False)
    assert result is None


async def test_user_data_from_jwe_async_relaxed() -> None:
    """user_data_from_jwe_async delegates to the sync implementation."""
    auth = _make_auth()
    result = await auth.user_data_from_jwe_async(
        "a.b.c.d.e", raise_exception=False
    )
    assert result is None

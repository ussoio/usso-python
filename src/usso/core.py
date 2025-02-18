import json
import logging
import os
from datetime import datetime, timedelta
from urllib.parse import urlparse

import cachetools.func
import httpx
import jwt

from .exceptions import USSOException
from .schemas import JWTConfig, UserData

logger = logging.getLogger("usso")


def get_authorization_scheme_param(
    authorization_header_value: str | None,
) -> tuple[str, str]:
    if not authorization_header_value:
        return "", ""
    scheme, _, param = authorization_header_value.partition(" ")
    return scheme, param


def decode_token(key, token: str, algorithms=["RS256"], **kwargs) -> dict:
    """Decode a JWT token."""
    try:
        decoded = jwt.decode(token, key, algorithms=algorithms)
        decoded.update({"data": decoded, "token": token})
        return UserData(**decoded)
    except jwt.ExpiredSignatureError:
        _handle_exception("expired_signature", **kwargs)
    except jwt.InvalidSignatureError:
        _handle_exception("invalid_signature", **kwargs)
    except jwt.InvalidAlgorithmError:
        _handle_exception("invalid_algorithm", **kwargs)
    except jwt.InvalidIssuedAtError:
        _handle_exception("invalid_issued_at", **kwargs)
    except jwt.InvalidTokenError:
        _handle_exception("invalid_token", **kwargs)
    except jwt.InvalidKeyError:
        _handle_exception("invalid_key", **kwargs)
    except Exception as e:
        _handle_exception("error", message=str(e), **kwargs)


def _handle_exception(error_type: str, **kwargs):
    """Handle JWT-related exceptions."""
    if kwargs.get("raise_exception", True):
        raise USSOException(
            status_code=401, error=error_type, message=kwargs.get("message")
        )
    logger.error(kwargs.get("message") or error_type)


def is_expired(token: str, **kwargs) -> bool:
    now = datetime.now()
    decoded_token: dict = jwt.decode(token, options={"verify_signature": False})
    exp = decoded_token.get("exp", (now + timedelta(days=1)).timestamp())
    exp = datetime.fromtimestamp(exp)
    return exp < now


@cachetools.func.ttl_cache(maxsize=128, ttl=10 * 60)
def get_jwk_keys(jwk_url: str) -> jwt.PyJWKClient:
    return jwt.PyJWKClient(jwk_url, headers={"User-Agent": "usso-python"})


def decode_token_with_jwk(jwk_url: str, token: str, **kwargs) -> UserData | None:
    """Return the user associated with a token value."""
    try:
        jwk_client = get_jwk_keys(jwk_url)
        signing_key = jwk_client.get_signing_key_from_jwt(token)
        return decode_token(signing_key.key, token, **kwargs)
    except Exception as e:
        _handle_exception("error", message=str(e), **kwargs)


@cachetools.func.ttl_cache(maxsize=128, ttl=10 * 60)
def fetch_api_key_data(jwk_url: str, api_key: str):
    try:
        parsed = urlparse(jwk_url)
        url = f"{parsed.scheme}://{parsed.netloc}/api_key/verify"
        response = httpx.post(url, json={"api_key": api_key})
        response.raise_for_status()
        return UserData(**response.json())
    except Exception as e:
        _handle_exception("error", message=str(e))



class Usso:
    def __init__(
        self,
        *,
        jwt_config: (
            str | dict | JWTConfig | list[str] | list[dict] | list[JWTConfig] | None
        ) = None,
        jwk_url: str | None = None,
        secret: str | None = None,
    ):
        self.jwt_configs = self._initialize_configs(jwt_config, jwk_url, secret)

    def _initialize_configs(
        self,
        jwt_config: (
            str | dict | JWTConfig | list[str] | list[dict] | list[JWTConfig] | None
        ) = None,
        jwk_url: str | None = None,
        secret: str | None = None,
    ):
        """Initialize JWT configurations."""
        if jwt_config is None:
            jwt_config = os.getenv("USSO_JWT_CONFIG")

        if jwt_config is None:
            jwk_url = jwk_url or os.getenv("USSO_JWK_URL") or os.getenv("USSO_JWKS_URL")
            secret = secret or os.getenv("USSO_SECRET")
            if jwk_url:
                return [JWTConfig(jwk_url=jwk_url)]
            if secret:
                return [JWTConfig(secret=secret)]
            raise ValueError(
                "Provide jwt_config, jwk_url, or secret, or set the appropriate environment variables."
            )

        if isinstance(jwt_config, (str, dict, JWTConfig)):
            return [self._parse_config(jwt_config)]
        if isinstance(jwt_config, list):
            return [self._parse_config(config) for config in jwt_config]
        raise ValueError("Invalid jwt_config format")

    def _parse_config(self, config):
        """Parse a single JWT configuration."""
        if isinstance(config, str):
            config = json.loads(config)
        if isinstance(config, dict):
            return JWTConfig(**config)
        return config

    def user_data_from_token(self, token: str, **kwargs) -> UserData | None:
        """Return the user associated with a token value."""
        exp = None
        for jwk_config in self.jwt_configs:
            try:
                user_data = jwk_config.decode(token)
                if user_data.token_type.lower() != kwargs.get("token_type", "access"):
                    _handle_exception("invalid_token_type", **kwargs)
                return user_data
            except USSOException as e:
                exp = e

        if kwargs.get("raise_exception", True):
            if exp:
                _handle_exception(exp.error, message=str(exp), **kwargs)
            _handle_exception("unauthorized", **kwargs)

    def user_data_from_api_key(self, api_key: str):
        return fetch_api_key_data(self.jwt_configs[0].jwk_url, api_key)

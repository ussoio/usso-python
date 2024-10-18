import json
import logging
import os
import uuid
from functools import lru_cache

import cachetools.func
import jwt
from pydantic import BaseModel, model_validator

from . import b64tools
from .exceptions import USSOException

logger = logging.getLogger("usso")


class UserData(BaseModel):
    user_id: str
    workspace_id: str | None = None
    workspace_ids: list[str] = []
    token_type: str = "access"

    email: str | None = None
    phone: str | None = None
    username: str | None = None

    authentication_method: str | None = None
    is_active: bool = False

    jti: str | None = None
    data: dict | None = None

    token: str | None = None

    @property
    def uid(self) -> uuid.UUID:
        user_id = self.user_id

        if user_id.startswith("u_"):
            user_id = user_id[2:]
        if 22 <= len(user_id) <= 24:
            user_id = b64tools.b64_decode_uuid(user_id)

        return uuid.UUID(user_id)

    @property
    def b64id(self) -> uuid.UUID:
        return b64tools.b64_encode_uuid_strip(self.uid)


def get_authorization_scheme_param(
    authorization_header_value: str | None,
) -> tuple[str, str]:
    if not authorization_header_value:
        return "", ""
    scheme, _, param = authorization_header_value.partition(" ")
    return scheme, param


def decode_token(key, token: str, algorithms=["RS256"], **kwargs) -> dict:
    try:
        decoded = jwt.decode(token, key, algorithms=algorithms)
        decoded["data"] = decoded
        decoded["token"] = token
        return UserData(**decoded)
    except jwt.exceptions.ExpiredSignatureError:
        if kwargs.get("raise_exception", True):
            raise USSOException(status_code=401, error="expired_signature")
    except jwt.exceptions.InvalidSignatureError:
        if kwargs.get("raise_exception", True):
            raise USSOException(status_code=401, error="invalid_signature")
    except jwt.exceptions.InvalidAlgorithmError:
        if kwargs.get("raise_exception", True):
            raise USSOException(status_code=401, error="invalid_algorithm")
    except jwt.exceptions.InvalidIssuedAtError:
        if kwargs.get("raise_exception", True):
            raise USSOException(status_code=401, error="invalid_issued_at")
    except jwt.exceptions.InvalidTokenError:
        if kwargs.get("raise_exception", True):
            raise USSOException(status_code=401, error="invalid_token")
    except jwt.exceptions.InvalidKeyError:
        if kwargs.get("raise_exception", True):
            raise USSOException(status_code=401, error="invalid_key")
    except USSOException as e:
        if kwargs.get("raise_exception", True):
            raise e
    except Exception as e:
        if kwargs.get("raise_exception", True):
            raise USSOException(status_code=401, error="error", message=str(e))
        logger.error(e)


@lru_cache
def get_jwk_keys(jwk_url: str) -> jwt.PyJWKClient:
    return jwt.PyJWKClient(jwk_url, headers={"User-Agent": "usso-python"})


def decode_token_jwk(jwk_url: str, token: str, **kwargs) -> UserData | None:
    """Return the user associated with a token value."""
    try:
        jwk_client = get_jwk_keys(jwk_url)
        signing_key = jwk_client.get_signing_key_from_jwt(token)
        return decode_token(signing_key.key, token, **kwargs)
    except USSOException as e:
        if kwargs.get("raise_exception", True):
            raise e
        logger.error(e)
    except Exception as e:
        if kwargs.get("raise_exception", True):
            raise USSOException(
                status_code=401,
                error="error",
                message=str(e),
            )
        logger.error(e)


class JWTConfig(BaseModel):
    jwk_url: str | None = None
    secret: str | None = None
    type: str = "RS256"
    header: dict[str, str] = {"type": "Cookie", "name": "usso_access_token"}

    def __hash__(self):
        return hash(self.model_dump_json())

    @model_validator(mode="before")
    def validate_secret(cls, data: dict):
        if not data.get("jwk_url") and not data.get("secret"):
            raise ValueError("Either jwk_url or secret must be provided")
        return data

    @classmethod
    @cachetools.func.ttl_cache(maxsize=128, ttl=10 * 60)
    def get_jwk_keys(cls, jwk_url):
        return get_jwk_keys(jwk_url)

    @cachetools.func.ttl_cache(maxsize=128, ttl=10 * 60)
    def decode(self, token: str):
        if self.jwk_url:
            return decode_token_jwk(self.jwk_url, token)
        return decode_token(self.secret, token, algorithms=[self.type])


class Usso:

    def __init__(
        self,
        *,
        jwt_config: str | dict | JWTConfig | list[str] | list[dict] | list[JWTConfig] | None = None,
        jwk_url: str | None = None,
        secret: str | None = None,
    ):
        if jwt_config is None:
            jwt_config = os.getenv("USSO_JWT_CONFIG")

        if jwt_config is None:
            if not jwk_url:
                jwk_url = os.getenv("USSO_JWK_URL") or os.getenv("USSO_JWKS_URL")
            if jwk_url:
                self.jwt_configs = [JWTConfig(jwk_url=jwk_url)]
                return
            
            if not secret:
                secret = os.getenv("USSO_SECRET")
            if secret:
                self.jwt_configs = [JWTConfig(secret=secret)]
                return

            raise ValueError(
                "\n".join(
                    [
                        "jwt_config or jwk_url or secret must be provided",
                        "or set the environment variable USSO_JWT_CONFIG or USSO_JWK_URL or USSO_SECRET",
                    ]
                )
            )

        def _get_config(jwt_config):
            if isinstance(jwt_config, str):
                jwt_config = json.loads(jwt_config)
            if isinstance(jwt_config, dict):
                jwt_config = JWTConfig(**jwt_config)
            return jwt_config

        if isinstance(jwt_config, str | dict | JWTConfig):
            jwt_config = [_get_config(jwt_config)]
        elif isinstance(jwt_config, list):
            jwt_config = [_get_config(j) for j in jwt_config]

        # self.jwk_url = jwt_config
        self.jwt_configs = jwt_config

    def user_data_from_token(self, token: str, **kwargs) -> UserData | None:
        """Return the user associated with a token value."""
        exp = None
        for jwk_config in self.jwt_configs:
            try:
                user_data = jwk_config.decode(token)
                if user_data.token_type.lower() != kwargs.get("token_type", "access"):
                    raise USSOException(
                        status_code=401,
                        error="invalid_token_type",
                        message="Token type must be 'access'",
                    )

                return user_data

            except USSOException as e:
                exp = e

        if kwargs.get("raise_exception", True):
            if exp:
                raise exp
            raise USSOException(
                status_code=401,
                error="unauthorized",
            )

import logging
import os
import uuid
from functools import lru_cache
from typing import Optional, Tuple

import cachetools.func
import jwt
from pydantic import BaseModel, model_validator
from singleton import Singleton

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


class Usso(metaclass=Singleton):
    def __init__(self, jwks_url: str | None = None):
        if jwks_url is None:
            jwks_url = os.getenv("USSO_JWKS_URL")
        self.jwks_url = jwks_url

    def get_jwk_keys(self):
        return get_jwk_keys(self.jwks_url)

    def get_authorization_scheme_param(
        self, authorization_header_value: Optional[str]
    ) -> Tuple[str, str]:
        return get_authorization_scheme_param(authorization_header_value)

    def user_data_from_token(self, token: str, **kwargs) -> UserData | None:
        """Return the user associated with a token value."""
        user_data = decode_token_jwk(self.jwks_url, token, **kwargs)
        if user_data.token_type.lower() != kwargs.get("token_type", "access"):
            raise USSOException(status_code=401, error="invalid_token_type")
        return user_data

    def user_data_from_token_none(self, token: str, **kwargs) -> UserData | None:
        try:
            return self.user_data_from_token(token, **kwargs)
        except USSOException:
            # logger.error(str(e))
            return None
        except Exception:
            # logger.error(str(e))
            return None

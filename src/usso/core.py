import logging
import os
import uuid
from functools import lru_cache
from typing import Optional, Tuple

import jwt
from pydantic import BaseModel
from singleton import Singleton

from . import b64tools
from .exceptions import USSOException

logger = logging.getLogger("usso")


class UserData(BaseModel):
    user_id: str
    email: str | None = None
    phone: str | None = None
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


class Usso(metaclass=Singleton):
    def __init__(self, jwks_url: str | None = None):
        if jwks_url is None:
            jwks_url = os.getenv("USSO_JWKS_URL")
        self.jwks_url = jwks_url

    @lru_cache
    def get_jwks_keys(self):
        return jwt.PyJWKClient(
            self.jwks_url,
            headers={
                "User-Agent": "usso-python",
            },
        )

    def get_authorization_scheme_param(
        self,
        authorization_header_value: Optional[str],
    ) -> Tuple[str, str]:
        if not authorization_header_value:
            return "", ""
        scheme, _, param = authorization_header_value.partition(" ")
        return scheme, param

    def decode_token(self, key, token: str, **kwargs) -> dict:
        try:
            decoded = jwt.decode(token, key, algorithms=["RS256"])
            if decoded["token_type"] != "access":
                raise USSOException(status_code=401, error="invalid_token_type")
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

    def user_data_from_token(self, token: str, **kwargs) -> UserData | None:
        """Return the user associated with a token value."""
        try:
            jwks_client = self.get_jwks_keys()
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            return self.decode_token(signing_key.key, token, **kwargs)
        except Exception as e:
            if kwargs.get("raise_exception", True):
                raise USSOException(
                    status_code=401,
                    error="error",
                    message=str(e),
                )
            logger.error(e)

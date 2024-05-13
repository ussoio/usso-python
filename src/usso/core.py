import os
import logging
import uuid
from functools import lru_cache
from typing import Optional, Tuple

import jwt
from pydantic import BaseModel

from . import b64tools
from .exceptions import USSOException

logger = logging.getLogger("usso")


class UserData(BaseModel):
    user_id: str
    email: str | None = None
    phone: str | None = None
    authentication_method: str | None = None
    is_active: bool = False
    jti: str
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
    authorization_header_value: Optional[str],
) -> Tuple[str, str]:
    if not authorization_header_value:
        return "", ""
    scheme, _, param = authorization_header_value.partition(" ")
    return scheme, param


def user_data_from_token(token: str, **kwargs) -> UserData | None:
    """Return the user associated with a token value."""
    try:
        header = jwt.get_unverified_header(token)
        jwks_url = header["jwk_url"]
        assert os.getenv("USSO_JWKS_URL") == jwks_url
        jwks_client = get_jwks_keys(jwks_url)
        # , headers=optional_custom_headers)
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        decoded = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
        )
        decoded["token"] = token

    except jwt.exceptions.ExpiredSignatureError:
        if kwargs.get("raise_exception"):
            raise USSOException(status_code=401, error="expired_signature")
        return None
    except jwt.exceptions.InvalidSignatureError:
        if kwargs.get("raise_exception"):
            raise USSOException(status_code=401, error="invalid_signature")
        return None
    except jwt.exceptions.InvalidTokenError:
        if kwargs.get("raise_exception"):
            raise USSOException(
                status_code=401,
                error="invalid_token",
            )
        return None
    except Exception as e:
        if kwargs.get("raise_exception"):
            raise USSOException(
                status_code=401,
                error="error",
                message=str(e),
            )
        logger.error(e)
        return None

    return UserData(**decoded)


@lru_cache
def get_jwks_keys(jwks_url):
    return jwt.PyJWKClient(jwks_url)

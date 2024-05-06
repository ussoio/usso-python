from functools import lru_cache
from typing import Optional, Tuple

import jwt
from pydantic import BaseModel


class UserData(BaseModel):
    user_id: str
    email: str | None = None
    phone: str | None = None
    authentication_method: str | None = None
    is_active: bool = False
    jti: str
    data: dict | None = None
    token: str | None = None


def get_authorization_scheme_param(
    authorization_header_value: Optional[str],
) -> Tuple[str, str]:
    if not authorization_header_value:
        return "", ""
    scheme, _, param = authorization_header_value.partition(" ")
    return scheme, param


@lru_cache
def get_jwks_keys(jwks_url):
    return jwt.PyJWKClient(jwks_url)

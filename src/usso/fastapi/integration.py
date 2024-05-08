import logging

import jwt
from fastapi import Request, WebSocket
from starlette.status import HTTP_401_UNAUTHORIZED

from usso.core import UserData, get_authorization_scheme_param, get_jwks_keys
from usso.exceptions import USSOException

logger = logging.getLogger("usso")


async def user_data_from_token(token: str, **kwargs) -> UserData | None:
    """Return the user associated with a token value."""
    try:
        header = jwt.get_unverified_header(token)
        jwks_url = header["jwk_url"]
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
            raise USSOException(
                status_code=HTTP_401_UNAUTHORIZED, error="expired_signature"
            )
        return None
    except jwt.exceptions.InvalidSignatureError:
        if kwargs.get("raise_exception"):
            raise USSOException(
                status_code=HTTP_401_UNAUTHORIZED, error="invalid_signature"
            )
        return None
    except jwt.exceptions.InvalidTokenError:
        if kwargs.get("raise_exception"):
            raise USSOException(
                status_code=HTTP_401_UNAUTHORIZED,
                error="invalid_token",
            )
        return None
    except Exception as e:
        if kwargs.get("raise_exception"):
            raise USSOException(
                status_code=HTTP_401_UNAUTHORIZED,
                error="error",
                message=str(e),
            )
        logger.error(e)
        return None

    return UserData(**decoded)


async def jwt_access_security(request: Request) -> UserData | None:
    """Return the user associated with a token value."""
    kwargs = {}
    authorization = request.headers.get("Authorization")
    if authorization:
        scheme, _, credentials = get_authorization_scheme_param(authorization)
        if scheme.lower() == "bearer":
            token = credentials
            return await user_data_from_token(token, **kwargs)

    cookie_token = request.cookies.get("access_token")
    if cookie_token:
        return await user_data_from_token(cookie_token, **kwargs)

    if kwargs.get("raise_exception", True):
        raise USSOException(
            status_code=HTTP_401_UNAUTHORIZED,
            error="unauthorized",
        )
    return None


async def jwt_access_security_ws(websocket: WebSocket) -> UserData | None:
    """Return the user associated with a token value."""
    kwargs = {}
    authorization = websocket.headers.get("Authorization")
    if authorization:
        scheme, _, credentials = get_authorization_scheme_param(authorization)
        if scheme.lower() == "bearer":
            token = credentials
            return await user_data_from_token(token, **kwargs)

    cookie_token = websocket.cookies.get("access_token")
    if cookie_token:
        return await user_data_from_token(cookie_token, **kwargs)

    if kwargs.get("raise_exception", True):
        raise USSOException(
            status_code=HTTP_401_UNAUTHORIZED,
            error="unauthorized",
        )
    return None

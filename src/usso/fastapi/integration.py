import logging

from fastapi import Request, WebSocket
from starlette.status import HTTP_401_UNAUTHORIZED

from usso.exceptions import USSOException

from ..core import UserData, Usso, get_authorization_scheme_param

logger = logging.getLogger("usso")


def get_request_token(request: Request | WebSocket) -> UserData | None:
    authorization = request.headers.get("Authorization")
    token = None

    if authorization:
        scheme, credentials = get_authorization_scheme_param(authorization)
        if scheme.lower() == "bearer":
            token = credentials

    else:
        cookie_token = request.cookies.get("usso_access_token")
        if cookie_token:
            token = cookie_token

    return token


def jwt_access_security_None(request: Request, jwt_config = None) -> UserData | None:
    """Return the user associated with a token value."""
    token = get_request_token(request)
    if not token:
        return None
    return Usso(jwt_config=jwt_config).user_data_from_token(token, raise_exception=False)


def jwt_access_security(request: Request, jwt_config=None) -> UserData | None:
    """Return the user associated with a token value."""
    token = get_request_token(request)
    if not token:
        raise USSOException(
            status_code=HTTP_401_UNAUTHORIZED,
            error="unauthorized",
            message="No token provided",
        )

    return Usso(jwt_config=jwt_config).user_data_from_token(token)


def jwt_access_security_ws(websocket: WebSocket, jwt_config=None) -> UserData | None:
    """Return the user associated with a token value."""
    token = get_request_token(websocket)
    if not token:
        raise USSOException(
            status_code=HTTP_401_UNAUTHORIZED,
            error="unauthorized",
            message="No token provided",
        )

    return Usso(jwt_config=jwt_config).user_data_from_token(token)

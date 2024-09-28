import logging

from fastapi import Request, WebSocket
from starlette.status import HTTP_401_UNAUTHORIZED

from usso.core import UserData, Usso
from usso.exceptions import USSOException

logger = logging.getLogger("usso")


def get_request_token(request: Request | WebSocket) -> UserData | None:
    authorization = request.headers.get("Authorization")
    token = None

    if authorization:
        scheme, credentials = Usso().get_authorization_scheme_param(authorization)
        if scheme.lower() == "bearer":
            token = credentials

    else:
        cookie_token = request.cookies.get("usso_access_token")
        if cookie_token:
            token = cookie_token

    return token


def jwt_access_security_None(request: Request) -> UserData | None:
    """Return the user associated with a token value."""
    token = get_request_token(request)
    if not token:
        return None
    return Usso().user_data_from_token(token, raise_exception=False)


def jwt_access_security(request: Request) -> UserData | None:
    """Return the user associated with a token value."""
    token = get_request_token(request)
    if not token:
        raise USSOException(
            status_code=HTTP_401_UNAUTHORIZED,
            error="unauthorized",
        )

    return Usso().user_data_from_token(token)


def jwt_access_security_ws(websocket: WebSocket) -> UserData | None:
    """Return the user associated with a token value."""
    token = get_request_token(websocket)
    if not token:
        raise USSOException(
            status_code=HTTP_401_UNAUTHORIZED,
            error="unauthorized",
        )

    return Usso().user_data_from_token(token)

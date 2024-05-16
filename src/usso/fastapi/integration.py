import logging

from fastapi import Request, WebSocket
from starlette.status import HTTP_401_UNAUTHORIZED

from usso.core import UserData, Usso
from usso.exceptions import USSOException

logger = logging.getLogger("usso")


async def jwt_access_security(request: Request) -> UserData | None:
    """Return the user associated with a token value."""
    kwargs = {}
    authorization = request.headers.get("Authorization")
    if authorization:
        scheme, _, credentials = Usso().get_authorization_scheme_param(
            authorization
        )
        if scheme.lower() == "bearer":
            token = credentials
            return Usso().user_data_from_token(token, **kwargs)

    cookie_token = request.cookies.get("usso_access_token")
    if cookie_token:
        return Usso().user_data_from_token(cookie_token, **kwargs)

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
        scheme, _, credentials = Usso().get_authorization_scheme_param(
            authorization
        )
        if scheme.lower() == "bearer":
            token = credentials
            return Usso().user_data_from_token(token, **kwargs)

    cookie_token = websocket.cookies.get("usso_access_token")
    if cookie_token:
        return Usso().user_data_from_token(cookie_token, **kwargs)

    if kwargs.get("raise_exception", True):
        raise USSOException(
            status_code=HTTP_401_UNAUTHORIZED,
            error="unauthorized",
        )
    return None

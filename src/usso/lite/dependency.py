"""FastAPI dependencies for USSO Lite."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ..exceptions import USSOException
from ..user import TokenType
from ..utils.string_utils import get_authorization_scheme_param
from .auth import LiteAuth
from .database import get_session
from .models import LocalSession, LocalUser

__all__ = ["get_auth", "get_current_user", "resolve_current_user"]

_auth: LiteAuth | None = None


def get_auth() -> LiteAuth:
    """Return the active LiteAuth instance (set by create_lite_router)."""
    if _auth is None:
        raise RuntimeError(
            "USSO Lite is not configured. Call create_lite_router() first."
        )
    return _auth


def _set_auth(auth: LiteAuth) -> None:
    global _auth
    _auth = auth


def extract_access_token(request: Request) -> str | None:
    """Extract a bearer token from the Authorization header or cookie."""
    authorization = request.headers.get("Authorization")
    if authorization:
        scheme, param = get_authorization_scheme_param(authorization)
        if scheme.lower() == "bearer" and param:
            return param
    cookie = request.cookies.get("usso-access-token")
    return cookie


async def get_current_user(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> LocalUser:
    """
    Resolve the authenticated user from the access token.

    Raises a 401 USSOException when the token is missing or invalid.
    """
    return await resolve_current_user(request, session, get_auth())


async def resolve_current_user(
    request: Request, session: AsyncSession, auth: LiteAuth
) -> LocalUser:
    """Resolve a current user using an explicit, application-local auth."""
    token = extract_access_token(request)
    if not token:
        raise USSOException(
            401,
            error_code="invalid_token",
            message={"en": "Unauthorized", "fa": "احراز هویت ناموفق"},
        )
    try:
        payload = auth.verify_token(token, expected_type=TokenType.ACCESS)
    except USSOException:
        raise
    except Exception:
        raise USSOException(
            401,
            error_code="invalid_token",
            message={"en": "Unauthorized", "fa": "احراز هویت ناموفق"},
        ) from None

    user = await auth.get_user(payload.uid, session)
    if user is None or not user.is_active or user.is_deleted:
        raise USSOException(
            401,
            error_code="user_not_active",
            message={"en": "Unauthorized", "fa": "حساب کاربری فعال نیست"},
        )
    auth_session = await session.get(LocalSession, payload.session_id or "")
    if (
        auth_session is None
        or auth_session.user_id != user.uid
        or not auth_session.is_active
        or auth_session.is_deleted
        or auth_session.is_expired
    ):
        raise USSOException(
            401,
            error_code="session_not_found",
            message={"en": "Unauthorized", "fa": "نشست معتبر نیست"},
        )
    return user

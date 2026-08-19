"""FastAPI router for USSO Lite."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from .. import authorization
from ..exceptions import PermissionDenied, USSOException
from .auth import LiteAuth
from .config import LiteConfig
from .database import LiteDatabase
from .dependency import resolve_current_user
from .models import LocalUser
from .schemas import (
    AuthResponse,
    ChangePasswordRequest,
    Identifier,
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    RequestOTPRequest,
    TokenPair,
    UserCreateRequest,
    UserResponse,
    UserUpdateRequest,
)

__all__ = ["create_lite_router"]

REFRESH_COOKIE_NAME = "usso-refresh-token"


async def _build_auth_response(
    auth: LiteAuth,
    user: LocalUser,
    pair: TokenPair,
    session: AsyncSession,
) -> AuthResponse:
    data = await auth.to_user_response(user, session)
    return AuthResponse(
        **data.model_dump(),
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        token_type=pair.token_type,
        expires_in=pair.expires_in,
    )


async def _jwks_flow(auth: LiteAuth) -> dict:
    """Expose the public Ed25519 key for standard JWT consumers."""
    return {"keys": [auth.access_key.jwk()]}


async def _register_flow(
    config: LiteConfig,
    auth: LiteAuth,
    payload: RegisterRequest,
    request: Request,
    session: AsyncSession,
) -> AuthResponse:
    """Register a new user and log them in."""
    if not config.allow_registration:
        raise PermissionDenied(
            error_code="registration_disabled",
            message={
                "en": "Public registration is disabled.",
                "fa": "ثبت‌نام عمومی غیرفعال است.",
            },
        )
    await auth._consume_rate_limit(
        action="registration",
        key=request.client.host if request.client else "unknown",
        limit=config.registration_limit,
        window_seconds=config.registration_window_seconds,
        session=session,
    )
    user = await auth.create_user(
        identifier=Identifier(
            type=payload.type, identifier=payload.identifier
        ),
        password=payload.secret,
        session=session,
        name=payload.name,
        roles=list(config.default_roles),
        scopes=list(config.default_scopes),
        is_active=True,
    )
    login = LoginRequest(
        type=payload.type,
        identifier=payload.identifier,
        method=payload.method,
        secret=payload.secret,
    )
    pair, _ = await auth.login(login, session)
    return await _build_auth_response(auth, user, pair, session)


async def _login_flow(
    auth: LiteAuth,
    payload: LoginRequest,
    request: Request,
    session: AsyncSession,
) -> AuthResponse:
    """Authenticate with an identifier and a password or OTP code."""
    pair, user = await auth.login(
        payload,
        session,
        user_agent=request.headers.get("user-agent"),
        ip=request.client.host if request.client else None,
    )
    return await _build_auth_response(auth, user, pair, session)


async def _refresh_flow(
    auth: LiteAuth,
    payload: RefreshRequest,
    session: AsyncSession,
) -> TokenPair:
    """Exchange a refresh token for a new token pair."""
    if not payload.refresh_token:
        raise USSOException(
            401,
            error_code="invalid_refresh_token",
            message={
                "en": "Refresh token is required.",
                "fa": "توکن تازه‌سازی الزامی است.",
            },
        )
    return await auth.refresh(payload.refresh_token, session)


async def _logout_flow(
    auth: LiteAuth,
    payload: RefreshRequest,
    session: AsyncSession,
) -> None:
    """End the session associated with the refresh token."""
    if not payload.refresh_token:
        raise USSOException(
            401,
            error_code="invalid_refresh_token",
            message={
                "en": "Refresh token is required.",
                "fa": "توکن تازه‌سازی الزامی است.",
            },
        )
    await auth.logout(payload.refresh_token, session)


def _refresh_request_from_cookie(request: Request) -> RefreshRequest:
    """Build a refresh request from the standard HttpOnly cookie."""
    return RefreshRequest(
        refresh_token=request.cookies.get(REFRESH_COOKIE_NAME),
    )


async def _request_otp_flow(
    config: LiteConfig,
    auth: LiteAuth,
    payload: RequestOTPRequest,
    request: Request,
    session: AsyncSession,
) -> dict:
    """Request an OTP code for an identifier."""
    await auth._consume_rate_limit(
        action="otp-request-client",
        key=request.client.host if request.client else "unknown",
        limit=config.otp_request_limit,
        window_seconds=config.otp_request_window_seconds,
        session=session,
    )
    code = await auth.request_otp(
        identifier=Identifier(
            type=payload.type, identifier=payload.identifier
        ),
        purpose=payload.purpose.value,
        session=session,
    )
    result = {"message": "OTP sent."}
    if config.expose_otp_in_response:
        result["code"] = code
    return result


async def _change_password_flow(
    auth: LiteAuth,
    user: LocalUser,
    payload: ChangePasswordRequest,
    session: AsyncSession,
) -> None:
    """Change the authenticated user's password."""
    await auth.change_password(
        user,
        old_password=payload.old_password,
        new_password=payload.new_password,
        session=session,
    )


async def _me_flow(
    auth: LiteAuth,
    user: LocalUser,
    session: AsyncSession,
) -> UserResponse:
    """Return the current user's profile."""
    return await auth.to_user_response(user, session)


async def _list_users_flow(
    auth: LiteAuth,
    session: AsyncSession,
    offset: int,
    limit: int,
) -> dict:
    """List users with pagination."""
    items, total = await auth.list_users(session, offset=offset, limit=limit)
    return {
        "items": [
            (await auth.to_user_response(u, session)).model_dump()
            for u in items
        ],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


async def _create_user_flow(
    auth: LiteAuth,
    payload: UserCreateRequest,
    session: AsyncSession,
) -> UserResponse:
    """Create a user directly (admin endpoint)."""
    user = await auth.create_user(
        identifier=Identifier(
            type=payload.type, identifier=payload.identifier
        ),
        password=payload.password,
        session=session,
        name=payload.name,
        roles=payload.roles,
        scopes=payload.scopes,
        is_active=payload.is_active,
    )
    return await auth.to_user_response(user, session)


async def _get_user_flow(
    auth: LiteAuth,
    uid: str,
    session: AsyncSession,
) -> UserResponse:
    """Return a user by uid."""
    user = await auth.get_user(uid, session)
    if user is None:
        raise USSOException(
            404,
            error_code="user_not_found",
            message={"en": "User not found", "fa": "کاربر پیدا نشد."},
        )
    return await auth.to_user_response(user, session)


async def _update_user_flow(
    auth: LiteAuth,
    uid: str,
    payload: UserUpdateRequest,
    session: AsyncSession,
) -> UserResponse:
    """Update a user by uid."""
    user = await auth.get_user(uid, session)
    if user is None:
        raise USSOException(
            404,
            error_code="user_not_found",
            message={"en": "User not found", "fa": "کاربر پیدا نشد."},
        )
    user = await auth.update_user(
        user, payload.model_dump(exclude_none=True), session
    )
    return await auth.to_user_response(user, session)


async def _delete_user_flow(
    auth: LiteAuth,
    uid: str,
    session: AsyncSession,
) -> None:
    """Delete a user by uid (soft delete)."""
    user = await auth.get_user(uid, session)
    if user is None:
        raise USSOException(
            404,
            error_code="user_not_found",
            message={"en": "User not found", "fa": "کاربر پیدا نشد."},
        )
    await auth.delete_user(user, session)


def _register_auth_routes(
    router: APIRouter,
    config: LiteConfig,
    auth: LiteAuth,
    database: LiteDatabase,
    router_auth: Callable[[], LiteAuth],
    current_user: Callable[..., object],
) -> None:
    """Register the authentication endpoints on the router."""
    auth_dep = Depends(router_auth)
    session_dep = Depends(database.get_session)

    @router.get("/.well-known/jwks.json", include_in_schema=False)
    async def jwks(auth: LiteAuth = auth_dep) -> dict:
        return await _jwks_flow(auth)

    @router.post("/auth/register", response_model=AuthResponse)
    async def register(
        payload: RegisterRequest,
        request: Request,
        auth: LiteAuth = auth_dep,
        session: AsyncSession = session_dep,
    ) -> AuthResponse:
        return await _register_flow(config, auth, payload, request, session)

    @router.post("/auth/login", response_model=AuthResponse)
    async def login(
        payload: LoginRequest,
        request: Request,
        auth: LiteAuth = auth_dep,
        session: AsyncSession = session_dep,
    ) -> AuthResponse:
        return await _login_flow(auth, payload, request, session)

    @router.get("/auth/refresh", response_model=TokenPair)
    async def refresh_cookie(
        request: Request,
        auth: LiteAuth = auth_dep,
        session: AsyncSession = session_dep,
    ) -> TokenPair:
        return await _refresh_flow(
            auth,
            _refresh_request_from_cookie(request),
            session,
        )

    @router.post("/auth/refresh", response_model=TokenPair)
    async def refresh(
        request: Request,
        payload: RefreshRequest | None = None,
        auth: LiteAuth = auth_dep,
        session: AsyncSession = session_dep,
    ) -> TokenPair:
        return await _refresh_flow(
            auth,
            payload or _refresh_request_from_cookie(request),
            session,
        )

    @router.post("/auth/logout", status_code=204, response_model=None)
    async def logout(
        payload: RefreshRequest,
        auth: LiteAuth = auth_dep,
        session: AsyncSession = session_dep,
    ) -> None:
        return await _logout_flow(auth, payload, session)

    @router.post("/auth/request-otp")
    async def request_otp(
        payload: RequestOTPRequest,
        request: Request,
        auth: LiteAuth = auth_dep,
        session: AsyncSession = session_dep,
    ) -> dict:
        return await _request_otp_flow(config, auth, payload, request, session)

    @router.post("/auth/password", status_code=204, response_model=None)
    async def change_password(
        payload: ChangePasswordRequest,
        user: LocalUser = Depends(current_user),
        auth: LiteAuth = auth_dep,
        session: AsyncSession = session_dep,
    ) -> None:
        return await _change_password_flow(auth, user, payload, session)


def _register_user_routes(
    router: APIRouter,
    auth: LiteAuth,
    database: LiteDatabase,
    router_auth: Callable[[], LiteAuth],
    current_user: Callable[..., object],
    admin_guard: Callable[..., object],
) -> None:
    """Register the user management endpoints on the router."""
    auth_dep = Depends(router_auth)
    session_dep = Depends(database.get_session)

    @router.get("/users/me", response_model=UserResponse)
    async def me(
        user: LocalUser = Depends(current_user),
        auth: LiteAuth = auth_dep,
        session: AsyncSession = session_dep,
    ) -> UserResponse:
        return await _me_flow(auth, user, session)

    @router.get("/users", response_model=dict)
    async def list_users(
        auth: LiteAuth = auth_dep,
        session: AsyncSession = session_dep,
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=20, ge=1, le=100),
        _admin: object = Depends(admin_guard),
    ) -> dict:
        return await _list_users_flow(auth, session, offset, limit)

    @router.post("/users", response_model=UserResponse)
    async def create_user(
        payload: UserCreateRequest,
        auth: LiteAuth = auth_dep,
        session: AsyncSession = session_dep,
        _admin: object = Depends(admin_guard),
    ) -> UserResponse:
        return await _create_user_flow(auth, payload, session)

    @router.get("/users/{uid}", response_model=UserResponse)
    async def get_user(
        uid: str,
        auth: LiteAuth = auth_dep,
        session: AsyncSession = session_dep,
        _admin: object = Depends(admin_guard),
    ) -> UserResponse:
        return await _get_user_flow(auth, uid, session)

    @router.patch("/users/{uid}", response_model=UserResponse)
    async def update_user(
        uid: str,
        payload: UserUpdateRequest,
        auth: LiteAuth = auth_dep,
        session: AsyncSession = session_dep,
        _admin: object = Depends(admin_guard),
    ) -> UserResponse:
        return await _update_user_flow(auth, uid, payload, session)

    @router.delete("/users/{uid}", status_code=204, response_model=None)
    async def delete_user(
        uid: str,
        auth: LiteAuth = auth_dep,
        session: AsyncSession = session_dep,
        _admin: object = Depends(admin_guard),
    ) -> None:
        return await _delete_user_flow(auth, uid, session)


def create_lite_router(
    config: LiteConfig,
    *,
    admin_dependency: Callable[..., object] | None = None,
) -> APIRouter:
    """
    Create the USSO Lite FastAPI router for the given config.

    Creates an isolated database/auth runtime and returns a router with the
    auth and user endpoints. Mount it on your app and register
    ``EXCEPTION_HANDLERS`` for clean errors. ``admin_dependency`` can provide
    a trusted bootstrap or application-specific administrative policy.
    """
    database = LiteDatabase(config.database_url)
    auth = LiteAuth(config)

    def router_auth() -> LiteAuth:
        return auth

    async def current_user(
        request: Request,
        session: AsyncSession = Depends(database.get_session),
    ) -> LocalUser:
        return await resolve_current_user(request, session, auth)

    @asynccontextmanager
    async def lifespan(_app: object) -> AsyncIterator[None]:
        await database.init_db()
        try:
            yield
        finally:
            await database.dispose()

    router = APIRouter(
        prefix=config.prefix,
        dependencies=[Depends(database.ensure_initialized)],
        lifespan=lifespan,
    )

    def require_admin(
        user: LocalUser = Depends(current_user),
    ) -> LocalUser:
        """Require the configured USSO-compatible administrative scope."""
        if not authorization.has_subset_scope(
            subset_scope=config.admin_scope,
            user_scopes=user.scopes,
        ):
            raise PermissionDenied()
        return user

    admin_guard = admin_dependency or require_admin

    _register_auth_routes(
        router, config, auth, database, router_auth, current_user
    )
    _register_user_routes(
        router, auth, database, router_auth, current_user, admin_guard
    )

    return router

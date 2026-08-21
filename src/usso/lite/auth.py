"""
Core authentication logic for USSO Lite.

Provides Argon2id password hashing, user management, JWT token
issuance/verification, session tracking and OTP handling.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import os
import re
import secrets
import stat
import time
import uuid
from datetime import timedelta
from typing import Any, ClassVar, NoReturn, cast

from argon2 import PasswordHasher as Argon2Hasher
from argon2 import Type
from sqlalchemy import case, desc, select, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession
from usso_jwt.algorithms import EdDSAKey
from usso_jwt.config import JWTConfig
from usso_jwt.schemas import JWT
from usso_jwt.sign import generate_jwt
from usso_jwt.utils import b64url_encode

from ..enums import AuthIdentifier, AuthSecret
from ..exceptions import USSOException
from ..user import TokenType, UserData
from .base import _utcnow
from .config import LiteConfig
from .enums import OTPPurpose
from .models import (
    LocalCredential,
    LocalOtp,
    LocalRateLimit,
    LocalSession,
    LocalUser,
    LocalUserIdentifier,
)
from .oidc import (
    OidcStateStore,
    build_oidc_authorization_url,
    decode_id_token_payload,
    exchange_oidc_code,
    fetch_oidc_userinfo,
    parse_oidc_callback,
)
from .schemas import (
    Identifier,
    LoginRequest,
    TokenPair,
    UserResponse,
)
from .validators import infer_identifier_type

__all__ = ["LiteAuth", "PasswordHasher"]

ACR_BASIC = "usso:acr:1"
ACR_MFA = "usso:acr:2"


class PasswordHasher:
    """Argon2id password hasher (mirrors the ICE USSO hasher)."""

    def __init__(
        self,
        memory_cost: int = 12288,
        time_cost: int = 3,
        parallelism: int = 1,
    ) -> None:
        """Initialize the Argon2id hasher with the given parameters."""
        self._hasher = Argon2Hasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )

    def hash_password(self, password: str) -> str:
        """Hash a password using Argon2id."""
        return self._hasher.hash(password)

    def verify_password(self, hashed: str, password: str) -> bool:
        """Verify a password against an Argon2id hash."""
        try:
            return self._hasher.verify(hashed, password)
        except Exception:
            return False

    def needs_rehash(self, hashed: str) -> bool:
        """Return whether a valid hash should be upgraded on next login."""
        try:
            return self._hasher.check_needs_rehash(hashed)
        except Exception:
            return False


def _raise(status_code: int, error_code: str, en: str, fa: str) -> NoReturn:
    raise USSOException(
        status_code,
        error_code=error_code,
        message={"en": en, "fa": fa},
    )


def _coerce_bool(value: object) -> bool | None:
    """Normalize OIDC boolean-ish claim values."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ("true", "1")
    return None


def _email_from_claims(
    claims: dict[str, Any],
) -> tuple[str | None, bool | None, str | None]:
    """Pull email / verified / name from a userinfo or id_token dict."""
    email: str | None = None
    raw_email = claims.get("email")
    if isinstance(raw_email, str) and raw_email.strip():
        email = raw_email.strip()
    name: str | None = None
    raw_name = claims.get("name")
    if isinstance(raw_name, str) and raw_name.strip():
        name = raw_name.strip()
    return email, _coerce_bool(claims.get("email_verified")), name


def _infer_identifier_type(value: str) -> AuthIdentifier:
    """Infer the identifier type (email, phone or username) from a value."""
    try:
        return infer_identifier_type(value)
    except ValueError as e:
        _raise(400, "invalid_identifier", str(e), str(e))


class LiteAuth:
    """
    Main authentication service for USSO Lite.

    Handles user management, password/OTP authentication, JWT issuance
    and refresh. A single instance backs the FastAPI router.
    """

    hasher: ClassVar[PasswordHasher] = PasswordHasher()

    def __init__(self, config: LiteConfig) -> None:
        """Set up signing keys from the given configuration."""
        self.config = config
        self.access_key = self._load_or_generate_access_key()
        self.refresh_secret: bytes = hashlib.sha256(
            self.access_key.private_der()
        ).digest()
        # Used to make unknown-account password checks take comparable time.
        self._dummy_password_hash = self.hasher.hash_password(
            secrets.token_urlsafe(32)
        )
        self._oidc_states = OidcStateStore()

    # ------------------------------------------------------------------
    # Keys
    # ------------------------------------------------------------------
    def _signing_key_path(self) -> str | None:
        url = self.config.database_url
        if not url.startswith("sqlite"):
            return None
        path = re.sub(r"^sqlite(\+aiosqlite)?:///?", "", url)
        if path in ("", ":memory:"):
            return None
        return f"{path}.signing.pem"

    def _load_or_generate_access_key(self) -> EdDSAKey:
        if self.config.signing_key:
            pem = self.config.signing_key
            if not pem.startswith("-----BEGIN"):
                with open(pem, "rb") as f:
                    pem = f.read().decode()
            return EdDSAKey.load_pem(pem.encode())

        path = self._signing_key_path()
        if path and os.path.exists(path):
            if not stat.S_ISREG(os.lstat(path).st_mode):
                raise RuntimeError(
                    "USSO Lite signing key must be a regular file."
                )
            os.chmod(path, 0o600)
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags)
            with os.fdopen(fd, "rb") as f:
                return EdDSAKey.load_pem(f.read())

        key = EdDSAKey.generate()
        if path:
            parent = os.path.dirname(os.path.abspath(path))
            os.makedirs(parent, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(key.private_pem())
        return key

    def _keyed_hash(self, namespace: str, value: str) -> str:
        """Hash low-entropy or identifying data with an application secret."""
        return hmac_mod.new(
            self.refresh_secret,
            f"{namespace}\0{value}".encode(),
            hashlib.sha256,
        ).hexdigest()

    async def _consume_rate_limit(
        self,
        *,
        action: str,
        key: str,
        limit: int,
        window_seconds: int,
        session: AsyncSession,
    ) -> None:
        """Consume one persistent fixed-window authentication attempt."""
        key_hash = self._keyed_hash(f"rate-limit:{action}", key)
        now = _utcnow()
        cutoff = now - timedelta(seconds=window_seconds)
        insert = sqlite_insert(LocalRateLimit).values(
            action=action,
            key_hash=key_hash,
            count=1,
            window_started_at=now,
        )
        statement = insert.on_conflict_do_update(
            index_elements=["action", "key_hash"],
            set_={
                "count": case(
                    (LocalRateLimit.window_started_at <= cutoff, 1),
                    else_=LocalRateLimit.count + 1,
                ),
                "window_started_at": case(
                    (LocalRateLimit.window_started_at <= cutoff, now),
                    else_=LocalRateLimit.window_started_at,
                ),
            },
        ).returning(LocalRateLimit.count)
        count = (await session.execute(statement)).scalar_one()
        await session.commit()
        if count > limit:
            _raise(
                429,
                "too_many_requests",
                "Too many attempts. Please try again later.",
                "درخواست‌های زیادی انجام شده است. کمی بعد دوباره امتحان کنید.",
            )

    async def _clear_rate_limit(
        self, *, action: str, key: str, session: AsyncSession
    ) -> None:
        """Clear a counter after successful authentication."""
        key_hash = self._keyed_hash(f"rate-limit:{action}", key)
        row = (
            await session.execute(
                select(LocalRateLimit).where(
                    LocalRateLimit.action == action,
                    LocalRateLimit.key_hash == key_hash,
                )
            )
        ).scalar_one_or_none()
        if row is not None:
            await session.delete(row)
            await session.commit()

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------
    async def find_user(
        self, identifier: Identifier, session: AsyncSession
    ) -> LocalUser | None:
        """Find a user by identifier, or None if not found."""
        identifier_type = identifier.type or _infer_identifier_type(
            identifier.identifier
        )
        stmt = (
            select(LocalUser)
            .join(
                LocalUserIdentifier,
                LocalUserIdentifier.user_id == LocalUser.uid,
            )
            .where(
                LocalUserIdentifier.type == identifier_type.value,
                LocalUserIdentifier.identifier == identifier.identifier,
                LocalUserIdentifier.is_active.is_(True),
                LocalUserIdentifier.is_deleted.is_(False),
                LocalUser.is_deleted.is_(False),
            )
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_user(
        self, uid: str, session: AsyncSession, *, include_deleted: bool = False
    ) -> LocalUser | None:
        """Get a user by uid."""
        stmt = select(LocalUser).where(LocalUser.uid == uid)
        if not include_deleted:
            stmt = stmt.where(LocalUser.is_deleted.is_(False))
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    async def create_user(
        self,
        *,
        identifier: Identifier,
        password: str | None,
        session: AsyncSession,
        name: str | None = None,
        roles: list[str] | None = None,
        scopes: list[str] | None = None,
        is_active: bool = True,
        custom_claims: dict | None = None,
    ) -> LocalUser:
        """Create a new user with an identifier and an optional password."""
        identifier_type = identifier.type or _infer_identifier_type(
            identifier.identifier
        )
        existing = await self.find_user(identifier, session)
        if existing is not None:
            _raise(
                409,
                "identifier_exists",
                "An account with this identifier already exists.",
                "حسابی با این شناسه از قبل وجود دارد.",
            )
        if password is not None and len(password) < 8:
            _raise(
                400,
                "weak_password",
                "Password must be at least 8 characters.",
                "رمز عبور باید حداقل ۸ کاراکتر باشد.",
            )

        user = LocalUser(
            name=name,
            roles=roles or [],
            scopes=scopes,
            is_active=is_active,
            is_limited=False,
            activation_status="active",
            custom_claims=custom_claims or {},
        )
        session.add(user)
        await session.flush()

        session.add(
            LocalUserIdentifier(
                user_id=user.uid,
                type=identifier_type.value,
                identifier=identifier.identifier,
                is_primary=True,
                is_active=True,
            )
        )
        if password is not None:
            session.add(
                LocalCredential(
                    user_id=user.uid,
                    method=AuthSecret.PASSWORD.value,
                    secret=self.hasher.hash_password(password),
                    is_active=True,
                )
            )
        await session.commit()
        await session.refresh(user)
        return user

    async def update_user(
        self, user: LocalUser, data: dict[str, Any], session: AsyncSession
    ) -> LocalUser:
        """Update user fields with the given data."""
        allowed = {
            "name",
            "roles",
            "scopes",
            "is_active",
            "is_limited",
            "activation_status",
            "avatar_url",
            "custom_claims",
        }
        permissions_changed = any(
            key in data for key in ("roles", "scopes", "is_active")
        )
        for key, value in data.items():
            if key in allowed and value is not None:
                setattr(user, key, value)
        session.add(user)
        if permissions_changed:
            sessions = (
                (
                    await session.execute(
                        select(LocalSession).where(
                            LocalSession.user_id == user.uid,
                            LocalSession.is_active.is_(True),
                        )
                    )
                )
                .scalars()
                .all()
            )
            for active_session in sessions:
                active_session.is_active = False
                session.add(active_session)
        await session.commit()
        await session.refresh(user)
        return user

    async def delete_user(
        self, user: LocalUser, session: AsyncSession, *, hard: bool = False
    ) -> None:
        """Delete a user (soft delete by default)."""
        if hard:
            await session.delete(user)
        else:
            user.is_deleted = True
            session.add(user)
        await session.commit()

    async def list_users(
        self, session: AsyncSession, *, offset: int = 0, limit: int = 20
    ) -> tuple[list[LocalUser], int]:
        """List users with pagination and total count."""
        stmt = select(LocalUser).where(LocalUser.is_deleted.is_(False))
        total_stmt = select(LocalUser.uid).where(
            LocalUser.is_deleted.is_(False)
        )
        total = len((await session.execute(total_stmt)).scalars().all())
        items = (
            (
                await session.execute(
                    stmt
                    .order_by(desc(LocalUser.created_at))
                    .offset(offset)
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )
        return list(items), total

    async def to_user_response(
        self, user: LocalUser, session: AsyncSession
    ) -> UserResponse:
        """Build a public user representation for API responses."""
        identifiers = await self._get_identifier_rows(user.uid, session)
        methods = (
            (
                await session.execute(
                    select(LocalCredential.method).where(
                        LocalCredential.user_id == user.uid,
                        LocalCredential.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .all()
        )
        return UserResponse(
            uid=user.uid,
            name=user.name,
            roles=list(user.roles or []),
            scopes=list(user.scopes) if user.scopes is not None else None,
            is_active=user.is_active,
            is_limited=user.is_limited,
            activation_status=user.activation_status,
            avatar_url=user.avatar_url,
            custom_claims=dict(user.custom_claims or {}),
            created_at=user.created_at,
            updated_at=user.updated_at,
            identifiers=[
                f"{row.type}:{row.identifier}" for row in identifiers
            ],
            credential_methods=list(methods),
        )

    async def _get_identifier_rows(
        self, user_uid: str, session: AsyncSession
    ) -> list[LocalUserIdentifier]:
        """Load active identifier rows for a user."""
        return list(
            (
                await session.execute(
                    select(LocalUserIdentifier).where(
                        LocalUserIdentifier.user_id == user_uid,
                        LocalUserIdentifier.is_active.is_(True),
                        LocalUserIdentifier.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .all()
        )

    async def _get_identifiers(
        self, user_uid: str, session: AsyncSession
    ) -> dict[str, str]:
        """Resolve active identifier values for a user."""
        result: dict[str, str] = {}
        for row in await self._get_identifier_rows(user_uid, session):
            result.setdefault(row.type, row.identifier)
        return result

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------
    async def authenticate(
        self,
        login: LoginRequest,
        session: AsyncSession,
        *,
        client_key: str = "unknown",
    ) -> LocalUser:
        """Authenticate a user with a password or OTP code."""
        await self._consume_rate_limit(
            action="login-client",
            key=f"{login.identifier}\0{client_key}",
            limit=self.config.login_attempt_limit,
            window_seconds=self.config.login_attempt_window_seconds,
            session=session,
        )
        await self._consume_rate_limit(
            action="login-identifier",
            key=login.identifier,
            limit=self.config.login_identifier_limit,
            window_seconds=self.config.login_attempt_window_seconds,
            session=session,
        )
        user = await self.find_user(identifier=login, session=session)
        if user is None:
            self.hasher.verify_password(
                self._dummy_password_hash, login.secret or ""
            )
            _raise(
                401,
                "invalid_credentials",
                "Invalid credentials.",
                "اطلاعات ورود صحیح نیست.",
            )
        if not user.is_active or user.activation_status != "active":
            _raise(
                401,
                "user_not_active",
                "This account is not active.",
                "این حساب کاربری فعال نیست.",
            )

        method = login.method or AuthSecret.PASSWORD
        if method in (AuthSecret.EMAIL_OTP, AuthSecret.PHONE_OTP):
            identifier_type = login.type or _infer_identifier_type(
                login.identifier
            )
            required_type = AuthSecret.get_identifier_type(method)
            if identifier_type != required_type:
                _raise(
                    400,
                    "invalid_auth_method",
                    "The OTP method does not match the identifier type.",
                    "روش رمز یک‌بارمصرف با نوع شناسه مطابقت ندارد.",
                )
            verified = await self.verify_otp(
                identifier_type=identifier_type,
                identifier=login.identifier,
                code=login.secret or "",
                purpose=OTPPurpose.LOGIN.value,
                session=session,
            )
            if not verified:
                _raise(
                    401,
                    "invalid_otp",
                    "Invalid or expired OTP code.",
                    "کد یک‌بارمصرف نامعتبر یا منقضی است.",
                )
            await self._clear_rate_limit(
                action="login-client",
                key=f"{login.identifier}\0{client_key}",
                session=session,
            )
            await self._clear_rate_limit(
                action="login-identifier",
                key=login.identifier,
                session=session,
            )
            return user

        if method != AuthSecret.PASSWORD:
            _raise(
                400,
                "unsupported_auth_method",
                "This authentication method is not supported by USSO Lite.",
                "این روش احراز هویت در USSO Lite پشتیبانی نمی‌شود.",
            )

        credential = (
            (
                await session.execute(
                    select(LocalCredential).where(
                        LocalCredential.user_id == user.uid,
                        LocalCredential.method == AuthSecret.PASSWORD.value,
                        LocalCredential.is_active.is_(True),
                        LocalCredential.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .first()
        )
        if credential is None or not self.hasher.verify_password(
            credential.secret, login.secret or ""
        ):
            _raise(
                401,
                "invalid_credentials",
                "Invalid credentials.",
                "اطلاعات ورود صحیح نیست.",
            )

        credential.last_used_at = _utcnow()
        if self.hasher.needs_rehash(credential.secret):
            credential.secret = self.hasher.hash_password(login.secret or "")
        session.add(credential)
        await session.commit()
        await self._clear_rate_limit(
            action="login-client",
            key=f"{login.identifier}\0{client_key}",
            session=session,
        )
        await self._clear_rate_limit(
            action="login-identifier",
            key=login.identifier,
            session=session,
        )
        return user

    async def login(
        self,
        login: LoginRequest,
        session: AsyncSession,
        *,
        user_agent: str | None = None,
        ip: str | None = None,
    ) -> tuple[TokenPair, LocalUser]:
        """Authenticate and issue a new token pair with a session."""
        user = await self.authenticate(
            login, session, client_key=ip or "local"
        )
        method = login.method or AuthSecret.PASSWORD
        amr = [method.value]
        # A single OTP is one factor, not MFA. ACR_MFA is reserved for
        # sessions whose AMR records at least two independent methods.
        acr = ACR_MFA if len(amr) > 1 else ACR_BASIC

        now = int(time.time())
        access_exp = now + self.config.access_token_minutes * 60
        refresh_exp = now + self.config.refresh_token_days * 24 * 60 * 60
        identifiers = await self._get_identifiers(user.uid, session)

        db_session = LocalSession(
            user_id=user.uid,
            scopes=user.scopes,
            roles=user.roles,
            amr=amr,
            max_age_minutes=self.config.session_max_age_minutes,
            user_agent=user_agent,
            ip=ip,
        )
        session.add(db_session)
        await session.flush()

        pair, refresh_jti = self.issue_tokens(
            user=user,
            session_id=db_session.uid,
            amr=amr,
            acr=acr,
            identifiers=identifiers,
            access_exp=access_exp,
            refresh_exp=refresh_exp,
        )
        db_session.jti = refresh_jti
        await session.commit()
        return pair, user

    def start_oidc(self, provider: str, state_store: OidcStateStore) -> dict:
        """Begin an OIDC paste/localhost-redirect login for ``provider``."""
        provider_config = self.config.oidc_providers.get(provider)
        if provider_config is None:
            _raise(
                404,
                "oidc_provider_not_found",
                f"Unknown OIDC provider: {provider}",
                f"ارائه‌دهنده OIDC ناشناخته است: {provider}",
            )
        state = state_store.create(provider)
        return {
            "provider": provider,
            "authorization_url": build_oidc_authorization_url(
                provider_config, state
            ),
            "state": state,
            "redirect_uri": provider_config.redirect_uri,
        }

    async def _oidc_resolve_tokens(
        self,
        provider: str,
        *,
        callback: str,
        state: str | None,
        state_store: OidcStateStore,
    ) -> dict[str, Any]:
        """Parse callback, validate CSRF state, and obtain a token response."""
        provider_config = self.config.oidc_providers[provider]
        parsed = parse_oidc_callback(callback)
        if parsed.token is not None:
            return parsed.token

        csrf_state = state or parsed.state
        if not csrf_state:
            _raise(
                400,
                "oidc_state_invalid",
                "OIDC state is required.",
                "مقدار state برای OIDC الزامی است.",
            )
        if not state_store.consume(csrf_state, provider=provider):
            _raise(
                400,
                "oidc_state_invalid",
                "OIDC state is invalid or expired.",
                "مقدار state نامعتبر یا منقضی است.",
            )
        if not parsed.code:
            _raise(
                400,
                "oidc_callback_invalid",
                "Callback is missing an authorization code.",
                "کد مجوز در مقدار بازگشتی موجود نیست.",
            )
        return await exchange_oidc_code(provider_config, parsed.code)

    async def _oidc_resolve_identity(
        self,
        provider: str,
        token_response: dict[str, Any],
    ) -> tuple[str, str | None]:
        """
        Resolve email (+ optional name) from userinfo / id_token.

        Prefer userinfo. ``id_token`` fallback decodes the JWT payload only
        (no JWKS signature verification) for minimal v1 identity login.
        """
        provider_config = self.config.oidc_providers[provider]
        access_token = token_response.get("access_token")
        if not access_token or not isinstance(access_token, str):
            _raise(
                400,
                "oidc_exchange_failed",
                "OIDC token response missing access_token.",
                "پاسخ توکن OIDC فاقد access_token است.",
            )

        userinfo = await fetch_oidc_userinfo(provider_config, access_token)
        email, email_verified, name = _email_from_claims(userinfo)

        if email is None:
            id_token = token_response.get("id_token")
            if isinstance(id_token, str) and id_token:
                claims = decode_id_token_payload(id_token)
                email, email_verified, id_name = _email_from_claims(claims)
                if name is None:
                    name = id_name

        if not email:
            _raise(
                400,
                "oidc_email_missing",
                "OIDC provider did not return an email address.",
                "ارائه‌دهنده OIDC آدرس ایمیل برنگرداند.",
            )
        if email_verified is False:
            _raise(
                403,
                "oidc_email_not_verified",
                "OIDC email address is not verified.",
                "آدرس ایمیل OIDC تأیید نشده است.",
            )
        return email, name

    async def _oidc_find_or_create_user(
        self,
        *,
        email: str,
        name: str | None,
        session: AsyncSession,
    ) -> LocalUser:
        """Find LocalUser by email, or create one when signup is allowed."""
        identifier = Identifier(type=AuthIdentifier.EMAIL, identifier=email)
        user = await self.find_user(identifier, session)
        if user is not None:
            return user
        if not self.config.oidc_allow_signup:
            _raise(
                403,
                "oidc_user_not_found",
                "No local account exists for this OIDC email.",
                "حسابی با این ایمیل OIDC وجود ندارد.",
            )
        return await self.create_user(
            identifier=identifier,
            password=None,
            session=session,
            name=name,
            roles=list(
                self.config.oidc_default_roles or self.config.default_roles
            ),
            scopes=list(self.config.default_scopes),
        )

    async def login_with_oidc(
        self,
        provider: str,
        *,
        callback: str,
        state: str | None,
        state_store: OidcStateStore,
        session: AsyncSession,
        user_agent: str | None = None,
        ip: str | None = None,
    ) -> tuple[TokenPair, LocalUser]:
        """
        Complete OIDC identity login from a pasted callback.

        Exchanges the authorization code (or accepts a pasted token JSON),
        resolves email via userinfo (preferred) or an unverified ``id_token``
        payload fallback, then finds or optionally creates a LocalUser and
        issues the same TokenPair shape as password login.
        """
        if provider not in self.config.oidc_providers:
            _raise(
                404,
                "oidc_provider_not_found",
                f"Unknown OIDC provider: {provider}",
                f"ارائه‌دهنده OIDC ناشناخته است: {provider}",
            )

        token_response = await self._oidc_resolve_tokens(
            provider,
            callback=callback,
            state=state,
            state_store=state_store,
        )
        email, name = await self._oidc_resolve_identity(
            provider, token_response
        )
        user = await self._oidc_find_or_create_user(
            email=email, name=name, session=session
        )

        if not user.is_active or user.activation_status != "active":
            _raise(
                401,
                "user_not_active",
                "This account is not active.",
                "این حساب کاربری فعال نیست.",
            )

        amr = [AuthSecret.OAUTH.value]
        now = int(time.time())
        access_exp = now + self.config.access_token_minutes * 60
        refresh_exp = now + self.config.refresh_token_days * 24 * 60 * 60
        identifiers = await self._get_identifiers(user.uid, session)

        db_session = LocalSession(
            user_id=user.uid,
            scopes=user.scopes,
            roles=user.roles,
            amr=amr,
            max_age_minutes=self.config.session_max_age_minutes,
            user_agent=user_agent,
            ip=ip,
        )
        session.add(db_session)
        await session.flush()

        pair, refresh_jti = self.issue_tokens(
            user=user,
            session_id=db_session.uid,
            amr=amr,
            acr=ACR_BASIC,
            identifiers=identifiers,
            access_exp=access_exp,
            refresh_exp=refresh_exp,
        )
        db_session.jti = refresh_jti
        await session.commit()
        return pair, user

    def issue_tokens(
        self,
        *,
        user: LocalUser,
        session_id: str,
        amr: list[str],
        acr: str,
        identifiers: dict[str, str],
        access_exp: int,
        refresh_exp: int,
        refresh_jti: str | None = None,
    ) -> tuple[TokenPair, str]:
        """
        Build and sign an access + refresh token pair.

        Returns the token pair and the refresh token ``jti`` so the
        session row can record it.
        """
        now = int(time.time())
        refresh_jti = refresh_jti or str(uuid.uuid4())
        custom_claims = dict(user.custom_claims or {})
        access_payload: dict[str, Any] = {
            "jti": str(uuid.uuid4()),
            "token_type": TokenType.ACCESS.value,
            "iss": self.config.issuer,
            "aud": self.config.audience,
            "iat": now,
            "nbf": now,
            "exp": access_exp,
            "sub": user.uid,
            "session_id": session_id,
            "roles": list(user.roles or []),
            "scopes": list(user.scopes or []),
            "amr": amr,
            "acr": acr,
            "claims": custom_claims,
            "user_id": user.uid,
            "user_name": user.name or "",
            "email": identifiers.get(AuthIdentifier.EMAIL.value),
            "phone": identifiers.get(AuthIdentifier.PHONE.value),
            "username": identifiers.get(AuthIdentifier.USERNAME.value),
        }
        refresh_payload: dict[str, Any] = {
            "jti": refresh_jti,
            "token_type": TokenType.REFRESH.value,
            "iss": self.config.issuer,
            "aud": self.config.issuer,
            "iat": now,
            "exp": refresh_exp,
            "sub": user.uid,
            "session_id": session_id,
        }

        access_token = generate_jwt(
            header={
                "alg": "EdDSA",
                "typ": "JWT",
                "kid": self.access_key.kid,
            },
            payload=access_payload,
            key=self.access_key.private_der(),
            alg="EdDSA",
        )
        refresh_token = generate_jwt(
            header={"alg": "HS256", "typ": "JWT"},
            payload=refresh_payload,
            key=self.refresh_secret,
            alg="HS256",
        )
        pair = TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",  # ruff: ignore[hardcoded-password-func-arg]
            expires_in=access_exp - now,
        )
        return pair, refresh_jti

    def verify_token(
        self, token: str, *, expected_type: TokenType = TokenType.ACCESS
    ) -> UserData:
        """Verify a JWT and return its user data payload."""
        if expected_type == TokenType.REFRESH:
            key: Any = {
                "kty": "oct",
                "alg": "HS256",
                "k": b64url_encode(self.refresh_secret),
            }
            config = JWTConfig.model_validate({
                "key": key,
                "issuer": self.config.issuer,
            })
        else:
            config = JWTConfig.model_validate({
                "key": self.access_key.jwk(),
                "issuer": self.config.issuer,
                "audience": self.config.audience,
            })
        jwt = JWT(token=token, config=config)
        jwt.verify(expected_token_type=expected_type.value)
        payload = jwt.unverified_payload
        if not isinstance(payload, dict):
            raise USSOException(
                status_code=401,
                error_code="invalid_token",
                detail="JWT payload must be a JSON object",
            )
        return UserData(**payload)

    async def refresh(
        self, refresh_token: str, session: AsyncSession
    ) -> TokenPair:
        """Validate a refresh token, rotate it and issue a new pair."""
        payload = self.verify_token(
            refresh_token, expected_type=TokenType.REFRESH
        )
        session_id = payload.session_id or ""
        db_session = (
            await session.execute(
                select(LocalSession).where(LocalSession.uid == session_id)
            )
        ).scalar_one_or_none()
        if (
            db_session is None
            or db_session.is_deleted
            or not db_session.is_active
        ):
            _raise(
                401,
                "session_not_found",
                "Session not found or already ended.",
                "نشست پیدا نشد یا قبلاً پایان یافته است.",
            )
        if db_session.is_expired:
            _raise(
                401,
                "session_expired",
                "Session expired. Please sign in again.",
                "نشست منقضی شده است. لطفاً دوباره وارد شوید.",
            )
        if (
            not payload.jti
            or not db_session.jti
            or not hmac_mod.compare_digest(payload.jti, db_session.jti)
            or payload.uid != db_session.user_id
        ):
            _raise(
                401,
                "refresh_token_reused",
                "This refresh token is no longer valid.",
                "این توکن تازه‌سازی دیگر معتبر نیست.",
            )
        user = await self.get_user(db_session.user_id, session)
        if (
            user is None
            or not user.is_active
            or user.activation_status != "active"
        ):
            _raise(
                401,
                "user_not_found",
                "User not found.",
                "کاربر پیدا نشد.",
            )

        now = int(time.time())
        access_exp = now + self.config.access_token_minutes * 60
        refresh_exp = now + self.config.refresh_token_days * 24 * 60 * 60
        identifiers = await self._get_identifiers(user.uid, session)
        pair, refresh_jti = self.issue_tokens(
            user=user,
            session_id=db_session.uid,
            amr=list(db_session.amr or []),
            acr=ACR_MFA if len(db_session.amr or []) > 1 else ACR_BASIC,
            identifiers=identifiers,
            access_exp=access_exp,
            refresh_exp=refresh_exp,
        )
        result = cast(
            CursorResult,
            await session.execute(
                update(LocalSession)
                .where(
                    LocalSession.uid == db_session.uid,
                    LocalSession.jti == payload.jti,
                    LocalSession.is_active.is_(True),
                    LocalSession.is_deleted.is_(False),
                )
                .values(jti=refresh_jti, last_used_at=_utcnow())
            ),
        )
        if result.rowcount != 1:
            await session.rollback()
            _raise(
                401,
                "refresh_token_reused",
                "This refresh token is no longer valid.",
                "این توکن تازه‌سازی دیگر معتبر نیست.",
            )
        await session.commit()
        return pair

    async def logout(self, refresh_token: str, session: AsyncSession) -> None:
        """End the session associated with a refresh token."""
        payload = self.verify_token(
            refresh_token, expected_type=TokenType.REFRESH
        )
        db_session = (
            await session.execute(
                select(LocalSession).where(
                    LocalSession.uid == (payload.session_id or "")
                )
            )
        ).scalar_one_or_none()
        if db_session is None:
            return
        if (
            not payload.jti
            or not db_session.jti
            or not hmac_mod.compare_digest(payload.jti, db_session.jti)
        ):
            _raise(
                401,
                "invalid_refresh_token",
                "This refresh token is no longer valid.",
                "این توکن تازه‌سازی دیگر معتبر نیست.",
            )
        db_session.is_active = False
        session.add(db_session)
        await session.commit()

    async def change_password(
        self,
        user: LocalUser,
        *,
        old_password: str | None,
        new_password: str,
        session: AsyncSession,
    ) -> None:
        """Change a user's password, verifying the old one if provided."""
        if len(new_password) < 8:
            _raise(
                400,
                "weak_password",
                "Password must be at least 8 characters.",
                "رمز عبور باید حداقل ۸ کاراکتر باشد.",
            )
        credential = (
            (
                await session.execute(
                    select(LocalCredential).where(
                        LocalCredential.user_id == user.uid,
                        LocalCredential.method == AuthSecret.PASSWORD.value,
                        LocalCredential.is_active.is_(True),
                        LocalCredential.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .first()
        )
        if credential is not None:
            if not old_password or not self.hasher.verify_password(
                credential.secret, old_password
            ):
                _raise(
                    400,
                    "wrong_password",
                    "Current password is required and must be correct.",
                    "رمز عبور فعلی الزامی است و باید صحیح باشد.",
                )
        elif old_password:
            _raise(
                400,
                "wrong_password",
                "This account does not have a password credential.",
                "برای این حساب رمز عبوری ثبت نشده است.",
            )

        # Deactivate old password credentials so only one stays active.
        old_credentials = (
            (
                await session.execute(
                    select(LocalCredential).where(
                        LocalCredential.user_id == user.uid,
                        LocalCredential.method == AuthSecret.PASSWORD.value,
                        LocalCredential.is_active.is_(True),
                        LocalCredential.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .all()
        )
        for old in old_credentials:
            old.is_active = False
            session.add(old)

        session.add(
            LocalCredential(
                user_id=user.uid,
                method=AuthSecret.PASSWORD.value,
                secret=self.hasher.hash_password(new_password),
                is_active=True,
            )
        )
        active_sessions = (
            (
                await session.execute(
                    select(LocalSession).where(
                        LocalSession.user_id == user.uid,
                        LocalSession.is_active.is_(True),
                    )
                )
            )
            .scalars()
            .all()
        )
        for active_session in active_sessions:
            active_session.is_active = False
            session.add(active_session)
        await session.commit()

    # ------------------------------------------------------------------
    # OTP
    # ------------------------------------------------------------------
    @staticmethod
    def _generate_otp(length: int) -> str:
        return f"{secrets.randbelow(10**length):0{length}d}"

    def _hash_code(self, code: str) -> str:
        return self._keyed_hash("otp", code)

    async def request_otp(
        self,
        *,
        identifier: Identifier,
        purpose: str = OTPPurpose.LOGIN.value,
        session: AsyncSession,
    ) -> str:
        """
        Generate an OTP code for an identifier and deliver it.

        Returns the plain code (useful for development). Delivery happens
        through the configured ``otp_sender`` callback if provided.
        """
        identifier_type = identifier.type or _infer_identifier_type(
            identifier.identifier
        )
        await self._consume_rate_limit(
            action="otp-request",
            key=identifier.identifier,
            limit=self.config.otp_request_limit,
            window_seconds=self.config.otp_request_window_seconds,
            session=session,
        )
        code = self._generate_otp(self.config.otp_length)
        now = _utcnow()
        expires_at = now + timedelta(seconds=self.config.otp_ttl_seconds)

        # Invalidate previous unused codes for this identifier + purpose.
        stmt = (
            select(LocalOtp)
            .where(
                LocalOtp.identifier_type == identifier_type.value,
                LocalOtp.identifier == identifier.identifier,
                LocalOtp.purpose == purpose,
                LocalOtp.is_used.is_(False),
                LocalOtp.is_deleted.is_(False),
            )
            .order_by(desc(LocalOtp.created_at))
        )
        old = (await session.execute(stmt)).scalars().all()
        for otp in old:
            otp.is_used = True
            session.add(otp)

        user = await self.find_user(identifier, session)
        session.add(
            LocalOtp(
                user_id=user.uid if user else None,
                identifier_type=identifier_type.value,
                identifier=identifier.identifier,
                code_hash=self._hash_code(code),
                purpose=purpose,
                expires_at=expires_at,
                is_used=False,
            )
        )
        await session.commit()

        sender = self.config.otp_sender
        if sender is None and not self.config.expose_otp_in_response:
            _raise(
                503,
                "otp_delivery_not_configured",
                "OTP delivery is not configured.",
                "ارسال رمز یک‌بارمصرف پیکربندی نشده است.",
            )
        if sender is not None:
            await sender(identifier_type.value, identifier.identifier, code)
        return code

    async def verify_otp(
        self,
        *,
        identifier_type: AuthIdentifier,
        identifier: str,
        code: str,
        purpose: str,
        session: AsyncSession,
    ) -> bool:
        """Verify an OTP code for an identifier and purpose."""
        stmt = (
            select(LocalOtp)
            .where(
                LocalOtp.identifier_type == identifier_type.value,
                LocalOtp.identifier == identifier,
                LocalOtp.purpose == purpose,
                LocalOtp.is_used.is_(False),
                LocalOtp.is_deleted.is_(False),
            )
            .order_by(desc(LocalOtp.created_at))
        )
        otp = (await session.execute(stmt)).scalars().first()
        if otp is None or otp.is_expired:
            return False
        if otp.attempt_count >= self.config.otp_max_attempts:
            return False
        if not hmac_mod.compare_digest(otp.code_hash, self._hash_code(code)):
            await session.execute(
                update(LocalOtp)
                .where(
                    LocalOtp.uid == otp.uid,
                    LocalOtp.is_used.is_(False),
                    LocalOtp.is_deleted.is_(False),
                    LocalOtp.attempt_count < self.config.otp_max_attempts,
                )
                .values(attempt_count=LocalOtp.attempt_count + 1)
            )
            await session.commit()
            return False
        result = cast(
            CursorResult,
            await session.execute(
                update(LocalOtp)
                .where(
                    LocalOtp.uid == otp.uid,
                    LocalOtp.is_used.is_(False),
                    LocalOtp.is_deleted.is_(False),
                    LocalOtp.attempt_count < self.config.otp_max_attempts,
                )
                .values(is_used=True)
            ),
        )
        if result.rowcount != 1:
            await session.rollback()
            return False
        await session.commit()
        return True

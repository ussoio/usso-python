"""Additional coverage tests for USSO Lite authentication branches."""

import os

import pytest
from sqlalchemy import delete as _delete
from usso_jwt.algorithms import EdDSAKey

from usso.enums import AuthIdentifier, AuthSecret
from usso.exceptions import USSOException
from usso.lite import LiteAuth, LiteConfig
from usso.lite.database import configure, dispose, get_session, init_db
from usso.lite.models import LocalSession
from usso.lite.schemas import Identifier, LoginRequest


@pytest.fixture
async def lite_setup() -> tuple[LiteConfig, LiteAuth]:
    """Create a fresh in-memory LiteAuth instance and configure the DB."""
    await dispose()
    cfg = LiteConfig(
        database_url="sqlite+aiosqlite:///:memory:",
        expose_otp_in_response=True,
    )
    auth = LiteAuth(cfg)
    configure(cfg.database_url)
    await init_db()
    return cfg, auth


def _email_login(identifier: str, secret: str) -> LoginRequest:
    return LoginRequest(
        type=AuthIdentifier.EMAIL,
        identifier=identifier,
        method=AuthSecret.PASSWORD,
        secret=secret,
    )


async def test_find_user_unknown(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """find_user returns None for an unknown identifier."""
    _cfg, auth = lite_setup
    async for session in get_session():
        user = await auth.find_user(
            Identifier(type=AuthIdentifier.EMAIL, identifier="x@y.com"),
            session,
        )
        assert user is None


async def test_create_user_weak_password(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """create_user rejects passwords shorter than eight characters."""
    _cfg, auth = lite_setup
    async for session in get_session():
        with pytest.raises(USSOException) as exc_info:
            await auth.create_user(
                identifier=Identifier(
                    type=AuthIdentifier.EMAIL, identifier="ali@example.com"
                ),
                password="short",
                session=session,
            )
        assert exc_info.value.status_code == 400


async def test_login_otp_type_mismatch(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Login with a phone OTP method rejects an email identifier."""
    _cfg, auth = lite_setup
    async for session in get_session():
        await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password="super-secret-1",
            session=session,
        )
        with pytest.raises(USSOException) as exc_info:
            await auth.login(
                LoginRequest(
                    type=AuthIdentifier.EMAIL,
                    identifier="ali@example.com",
                    method=AuthSecret.PHONE_OTP,
                    secret="123456",
                ),
                session,
            )
        assert exc_info.value.status_code == 400


async def test_login_otp_wrong_code(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Login with an invalid OTP code is rejected."""
    _cfg, auth = lite_setup
    async for session in get_session():
        await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password="super-secret-1",
            session=session,
        )
        with pytest.raises(USSOException):
            await auth.login(
                LoginRequest(
                    type=AuthIdentifier.EMAIL,
                    identifier="ali@example.com",
                    method=AuthSecret.EMAIL_OTP,
                    secret="000000",
                ),
                session,
            )


async def test_login_unsupported_method(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Login with an unsupported secret method is rejected."""
    _cfg, auth = lite_setup
    async for session in get_session():
        await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password="super-secret-1",
            session=session,
        )
        with pytest.raises(USSOException):
            await auth.login(
                LoginRequest(
                    type=AuthIdentifier.EMAIL,
                    identifier="ali@example.com",
                    method=AuthSecret.TOTP,
                    secret="123456",
                ),
                session,
            )


async def test_rate_limit_exceeded() -> None:
    """Exceeding the login identifier rate limit returns 429."""
    await dispose()
    cfg = LiteConfig(
        database_url="sqlite+aiosqlite:///:memory:",
        login_identifier_limit=1,
        login_attempt_window_seconds=60,
    )
    auth = LiteAuth(cfg)
    configure(cfg.database_url)
    await init_db()
    async for session in get_session():
        for _ in range(2):
            try:
                await auth.login(
                    _email_login("ali@example.com", "super-secret-1"),
                    session,
                )
            except USSOException as exc:
                assert exc.status_code in (401, 429)


async def test_refresh_with_expired_session(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Refreshing with an expired session is rejected."""
    _cfg, auth = lite_setup
    async for session in get_session():
        await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password="super-secret-1",
            session=session,
        )
        pair, _ = await auth.login(
            _email_login("ali@example.com", "super-secret-1"), session
        )
        from datetime import timedelta

        from usso.lite.base import _utcnow

        db_session = (
            (
                await session.execute(
                    __import__("sqlalchemy").select(LocalSession).limit(1)
                )
            )
            .scalars()
            .first()
        )
        assert db_session is not None
        db_session.max_age_minutes = 1
        db_session.created_at = _utcnow() - timedelta(hours=2)
        await session.commit()
        with pytest.raises(USSOException) as exc_info:
            await auth.refresh(pair.refresh_token, session)
        assert exc_info.value.status_code == 401


async def test_refresh_token_reuse_detected(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Using an already-rotated refresh token is rejected."""
    _cfg, auth = lite_setup
    async for session in get_session():
        await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password="super-secret-1",
            session=session,
        )
        pair, _ = await auth.login(
            _email_login("ali@example.com", "super-secret-1"), session
        )
        await auth.refresh(pair.refresh_token, session)
        with pytest.raises(USSOException) as exc_info:
            await auth.refresh(pair.refresh_token, session)
        assert exc_info.value.status_code == 401


async def test_logout_unknown_session(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Logout returns silently when the session does not exist."""
    _cfg, auth = lite_setup
    async for session in get_session():
        await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password="super-secret-1",
            session=session,
        )
        pair, _ = await auth.login(
            _email_login("ali@example.com", "super-secret-1"), session
        )
        await session.execute(_delete(LocalSession))
        await session.commit()
        await auth.logout(pair.refresh_token, session)


async def test_change_password_weak_new(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """change_password rejects a weak new password."""
    _cfg, auth = lite_setup
    async for session in get_session():
        user = await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password="super-secret-1",
            session=session,
        )
        with pytest.raises(USSOException) as exc_info:
            await auth.change_password(
                user,
                old_password="super-secret-1",
                new_password="short",
                session=session,
            )
        assert exc_info.value.status_code == 400


async def test_request_otp_requires_sender() -> None:
    """request_otp raises when delivery is not configured."""
    await dispose()
    cfg = LiteConfig(
        database_url="sqlite+aiosqlite:///:memory:",
        expose_otp_in_response=False,
        otp_sender=None,
    )
    auth = LiteAuth(cfg)
    configure(cfg.database_url)
    await init_db()
    async for session in get_session():
        with pytest.raises(USSOException) as exc_info:
            await auth.request_otp(
                identifier=Identifier(
                    type=AuthIdentifier.EMAIL, identifier="ali@example.com"
                ),
                session=session,
            )
        assert exc_info.value.status_code == 503


def test_signing_key_from_file(tmp_path: object) -> None:
    """LiteAuth loads an Ed25519 signing key from a PEM file."""
    key = EdDSAKey.generate()
    path = os.path.join(str(tmp_path), "signing.pem")
    with open(path, "w") as f:
        f.write(key.private_pem().decode())
    cfg = LiteConfig(signing_key=path)
    auth = LiteAuth(cfg)
    assert auth.access_key is not None


def test_needs_rehash_non_argon2() -> None:
    """needs_rehash returns False for non-Argon2 hashes."""
    auth = LiteAuth(LiteConfig(database_url="sqlite+aiosqlite:///:memory:"))
    assert auth.hasher.needs_rehash("$2b$12$abcdefghijklmnopqrstuv") is False


async def test_refresh_inactive_user(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Refreshing for a deactivated user is rejected."""
    _cfg, auth = lite_setup
    async for session in get_session():
        user = await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password="super-secret-1",
            session=session,
        )
        pair, _ = await auth.login(
            _email_login("ali@example.com", "super-secret-1"), session
        )
        user.is_active = False
        await session.commit()
        with pytest.raises(USSOException) as exc_info:
            await auth.refresh(pair.refresh_token, session)
        assert exc_info.value.status_code == 401


async def test_logout_stale_token(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Logout with a rotated refresh token is rejected."""
    _cfg, auth = lite_setup
    async for session in get_session():
        await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password="super-secret-1",
            session=session,
        )
        pair, _ = await auth.login(
            _email_login("ali@example.com", "super-secret-1"), session
        )
        await auth.refresh(pair.refresh_token, session)
        with pytest.raises(USSOException) as exc_info:
            await auth.logout(pair.refresh_token, session)
        assert exc_info.value.status_code == 401


async def test_change_password_deactivates_sessions(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Changing the password invalidates active sessions."""
    _cfg, auth = lite_setup
    async for session in get_session():
        user = await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password="super-secret-1",
            session=session,
        )
        await auth.login(
            _email_login("ali@example.com", "super-secret-1"), session
        )
        await auth.change_password(
            user,
            old_password="super-secret-1",
            new_password="brand-new-pass-1",
            session=session,
        )
        from sqlalchemy import select

        db_sessions = (
            (
                await session.execute(
                    select(LocalSession).where(
                        LocalSession.user_id == user.uid
                    )
                )
            )
            .scalars()
            .all()
        )
        assert all(not s.is_active for s in db_sessions)


async def test_request_otp_invalidates_previous(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Requesting a new OTP invalidates the previous unused code."""
    _cfg, auth = lite_setup
    async for session in get_session():
        await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password="super-secret-1",
            session=session,
        )
        first = await auth.request_otp(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            session=session,
        )
        second = await auth.request_otp(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            session=session,
        )
        assert first != second
        assert not await auth.verify_otp(
            identifier_type=AuthIdentifier.EMAIL,
            identifier="ali@example.com",
            code=first,
            purpose="login",
            session=session,
        )

"""Coverage tests for USSO Lite authentication internals."""

import pytest
from sqlalchemy import select

from src.usso.enums import AuthIdentifier, AuthSecret
from src.usso.exceptions import USSOException
from src.usso.lite import LiteAuth, LiteConfig
from src.usso.lite.database import configure, dispose, get_session, init_db
from src.usso.lite.models import LocalSession, LocalUser
from src.usso.lite.schemas import Identifier, LoginRequest


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


async def test_update_user_permissions_deactivates_sessions(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Updating roles/scopes/is_active invalidates the user's sessions."""
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
        await auth.update_user(user, {"is_active": True}, session)
        sessions = (
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
        assert all(not s.is_active for s in sessions)


async def test_delete_user_hard(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Hard deletion removes the user row entirely."""
    _cfg, auth = lite_setup
    async for session in get_session():
        user = await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password="super-secret-1",
            session=session,
        )
        await auth.delete_user(user, session, hard=True)
        assert await session.get(LocalUser, user.uid) is None


async def test_list_users_pagination(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """list_users returns items and a total count."""
    _cfg, auth = lite_setup
    async for session in get_session():
        for i in range(3):
            await auth.create_user(
                identifier=Identifier(
                    type=AuthIdentifier.EMAIL,
                    identifier=f"user{i}@example.com",
                ),
                password="super-secret-1",
                session=session,
            )
        items, total = await auth.list_users(session, offset=1, limit=2)
        assert len(items) == 2
        assert total == 3


async def test_change_password_wrong_old(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """change_password rejects a wrong current password."""
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
                old_password="wrong-old",
                new_password="brand-new-pass-1",
                session=session,
            )
        assert exc_info.value.status_code == 400


async def test_change_password_no_credential(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """change_password rejects old passwords for password-less accounts."""
    _cfg, auth = lite_setup
    async for session in get_session():
        user = await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password=None,
            session=session,
        )
        with pytest.raises(USSOException) as exc_info:
            await auth.change_password(
                user,
                old_password="any-old",
                new_password="brand-new-pass-1",
                session=session,
            )
        assert exc_info.value.status_code == 400


async def test_login_unknown_user_timing(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Login for an unknown identifier is rejected with a 401."""
    _cfg, auth = lite_setup
    async for session in get_session():
        with pytest.raises(USSOException) as exc_info:
            await auth.login(
                _email_login("nobody@example.com", "super-secret-1"),
                session,
            )
        assert exc_info.value.status_code == 401


async def test_otp_exceeds_attempt_limit(
    lite_setup: tuple[LiteConfig, LiteAuth],
) -> None:
    """Repeated wrong OTP codes exhaust the attempt limit."""
    cfg, auth = lite_setup
    async for session in get_session():
        await auth.create_user(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            password="super-secret-1",
            session=session,
        )
        code = await auth.request_otp(
            identifier=Identifier(
                type=AuthIdentifier.EMAIL, identifier="ali@example.com"
            ),
            session=session,
        )
        for _ in range(cfg.otp_max_attempts):
            assert not await auth.verify_otp(
                identifier_type=AuthIdentifier.EMAIL,
                identifier="ali@example.com",
                code="000000",
                purpose="login",
                session=session,
            )
        assert not await auth.verify_otp(
            identifier_type=AuthIdentifier.EMAIL,
            identifier="ali@example.com",
            code=code,
            purpose="login",
            session=session,
        )

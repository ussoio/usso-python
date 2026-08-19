"""
SQLAlchemy models for USSO Lite.

These models mirror the ICE USSO concepts (User, UserIdentifier,
Credential, AuthSession, OTP) without tenant scoping.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import (
    JSON,
    DateTime,
    Index,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, BaseEntity, UserEntity, _utcnow

__all__ = [
    "LocalCredential",
    "LocalOtp",
    "LocalRateLimit",
    "LocalSession",
    "LocalUser",
    "LocalUserIdentifier",
]


class LocalUser(Base, BaseEntity):
    """A single-tenant user account."""

    __tablename__ = "localuser"

    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    roles: Mapped[list[str]] = mapped_column(JSON, default=list)
    scopes: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    is_active: Mapped[bool] = mapped_column(default=False)
    is_limited: Mapped[bool] = mapped_column(default=False)
    activation_status: Mapped[str] = mapped_column(
        String(32), default="active"
    )
    avatar_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    custom_claims: Mapped[dict] = mapped_column(JSON, default=dict)

    identifiers: Mapped[list[LocalUserIdentifier]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    credentials: Mapped[list[LocalCredential]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    sessions: Mapped[list[LocalSession]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class LocalUserIdentifier(Base, UserEntity):
    """A user identifier (email, phone, username, ...)."""

    __tablename__ = "localuseridentifier"

    type: Mapped[str] = mapped_column(String(32))
    identifier: Mapped[str] = mapped_column(String(512))
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    is_primary: Mapped[bool] = mapped_column(default=False)
    is_active: Mapped[bool] = mapped_column(default=True)

    user: Mapped[LocalUser] = relationship(back_populates="identifiers")

    __table_args__ = (
        UniqueConstraint(
            "type", "identifier", "is_deleted", name="uq_identifier_unique"
        ),
        Index("ix_identifier_type", "type", "identifier"),
    )


class LocalCredential(Base, UserEntity):
    """A user credential (hashed password, ...)."""

    __tablename__ = "localcredential"

    method: Mapped[str] = mapped_column(String(32))
    secret: Mapped[str] = mapped_column(String(512))
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    is_active: Mapped[bool] = mapped_column(default=True)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )

    user: Mapped[LocalUser] = relationship(back_populates="credentials")


class LocalSession(Base, UserEntity):
    """An authentication session, tracked for refresh and logout."""

    __tablename__ = "localsession"

    jti: Mapped[str | None] = mapped_column(String(128), nullable=True)
    scopes: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    roles: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    amr: Mapped[list[str]] = mapped_column(JSON, default=list)
    max_age_minutes: Mapped[int | None] = mapped_column(nullable=True)
    last_used_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    is_active: Mapped[bool] = mapped_column(default=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    session_type: Mapped[str] = mapped_column(
        String(32), default="regular_login"
    )

    user: Mapped[LocalUser] = relationship(back_populates="sessions")

    __table_args__ = (Index("ix_session_jti", "jti"),)

    @property
    def expire_at(self) -> datetime | None:
        """Session expiration timestamp (None if it never expires)."""
        if self.max_age_minutes is None:
            return None
        return self.created_at + timedelta(minutes=self.max_age_minutes)

    @property
    def is_expired(self) -> bool:
        """Whether the session has expired."""
        expire_at = self.expire_at
        if expire_at is None:
            return False
        return expire_at < _utcnow()


class LocalOtp(Base, UserEntity):
    """A short-lived one-time password record."""

    __tablename__ = "localotp"

    identifier_type: Mapped[str] = mapped_column(String(32))
    identifier: Mapped[str] = mapped_column(String(512))
    code_hash: Mapped[str] = mapped_column(String(128))
    purpose: Mapped[str] = mapped_column(String(32), default="login")
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    is_used: Mapped[bool] = mapped_column(default=False)
    attempt_count: Mapped[int] = mapped_column(default=0)

    __table_args__ = (
        Index("ix_otp_identifier", "identifier_type", "identifier"),
    )

    @property
    def is_expired(self) -> bool:
        """Whether the OTP code has expired."""
        return self.expires_at < _utcnow()


class LocalRateLimit(Base, BaseEntity):
    """Persistent fixed-window counter for sensitive authentication actions."""

    __tablename__ = "localratelimit"

    action: Mapped[str] = mapped_column(String(32))
    key_hash: Mapped[str] = mapped_column(String(64))
    count: Mapped[int] = mapped_column(default=0)
    window_started_at: Mapped[datetime] = mapped_column(
        DateTime, default=_utcnow
    )

    __table_args__ = (
        UniqueConstraint("action", "key_hash", name="uq_rate_limit_key"),
    )

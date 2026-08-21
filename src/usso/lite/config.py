"""Configuration for USSO Lite."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from pydantic import BaseModel, Field

__all__ = ["LiteConfig", "OidcProviderConfig"]

OtpSender = Callable[
    [str, str, str], Awaitable[Any]
]  # (identifier_type, identifier, code) -> delivered


class OidcProviderConfig(BaseModel):
    """OIDC identity provider settings (openid/email/profile only)."""

    client_id: str
    client_secret: str
    redirect_uri: str = "http://localhost"
    authorize_url: str = "https://accounts.google.com/o/oauth2/v2/auth"
    token_url: str = (
        "https://oauth2.googleapis.com/token"  # ruff: ignore[hardcoded-password-string]
    )
    userinfo_url: str = "https://openidconnect.googleapis.com/v1/userinfo"
    scopes: list[str] = Field(
        default_factory=lambda: ["openid", "email", "profile"]
    )


class LiteConfig(BaseModel):
    """
    Configuration for the USSO Lite identity layer.

    Attributes:
        database_url: SQLAlchemy async URL (defaults to a local SQLite file).
        prefix: URL prefix the router is mounted under (default empty).
        signing_key: Ed25519 private key as a PEM string or a path to a
            PEM file. If unset, a key is generated once and persisted next
            to the SQLite database so tokens survive restarts.
        issuer: JWT ``iss`` claim.
        audience: JWT ``aud`` claim.
        access_token_minutes: Access token lifetime in minutes.
        refresh_token_days: Refresh token lifetime in days.
        session_max_age_minutes: Maximum session lifetime; refresh tokens
            beyond this age are rejected. None means sessions never expire.
        otp_length: Number of digits in generated OTP codes.
        otp_ttl_seconds: OTP validity window in seconds.
        otp_max_attempts: Failed verification attempts allowed before an
            OTP code is invalidated.
        otp_sender: Optional async callback used to deliver OTP codes.
            Receives ``(identifier_type, identifier, code)``.
        oidc_providers: Named OIDC identity providers (e.g. ``google``).
        oidc_allow_signup: Create a LocalUser on first OIDC login when True.
        oidc_default_roles: Roles applied when OIDC signup creates a user.
    """

    database_url: str = Field(default="sqlite+aiosqlite:///./usso_lite.db")
    prefix: str = Field(default="")
    signing_key: str | None = Field(
        default=None, description="Ed25519 PEM string or path to a PEM file."
    )
    issuer: str = Field(default="usso-lite")
    audience: str = Field(default="usso-lite")
    access_token_minutes: int = Field(default=10, ge=1)
    refresh_token_days: int = Field(default=30, ge=1)
    session_max_age_minutes: int | None = Field(default=43200, ge=1)
    allow_registration: bool = Field(default=True)
    default_roles: list[str] = Field(default_factory=list)
    default_scopes: list[str] = Field(default_factory=list)
    admin_scope: str = Field(default="admin:usso/lite/users")
    otp_length: int = Field(default=6, ge=4, le=10)
    otp_ttl_seconds: int = Field(default=300, ge=30)
    otp_max_attempts: int = Field(default=5, ge=1)
    otp_request_limit: int = Field(default=3, ge=1)
    otp_request_window_seconds: int = Field(default=300, ge=1)
    login_attempt_limit: int = Field(default=5, ge=1)
    login_attempt_window_seconds: int = Field(default=300, ge=1)
    login_identifier_limit: int = Field(default=20, ge=1)
    registration_limit: int = Field(default=5, ge=1)
    registration_window_seconds: int = Field(default=3600, ge=1)
    expose_otp_in_response: bool = Field(default=False)
    otp_sender: OtpSender | None = Field(default=None, exclude=True)
    oidc_providers: dict[str, OidcProviderConfig] = Field(default_factory=dict)
    oidc_allow_signup: bool = Field(default=False)
    oidc_default_roles: list[str] = Field(default_factory=list)

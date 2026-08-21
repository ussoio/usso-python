"""Pydantic schemas for USSO Lite."""

from __future__ import annotations

from datetime import datetime
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..enums import AuthIdentifier, AuthSecret
from .enums import OTPPurpose
from .validators import canonicalize_identifier, infer_identifier_type

__all__ = [
    "AuthResponse",
    "ChangePasswordRequest",
    "Identifier",
    "LoginRequest",
    "OidcCompleteRequest",
    "OidcStartRequest",
    "OidcStartResponse",
    "RefreshRequest",
    "RegisterRequest",
    "RequestOTPRequest",
    "Secret",
    "TokenPair",
    "UserCreateRequest",
    "UserResponse",
    "UserUpdateRequest",
]


class Identifier(BaseModel):
    """A user identifier (email, phone or username)."""

    model_config = ConfigDict(extra="forbid")

    type: AuthIdentifier | None = Field(default=None)
    identifier: str = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def _canonicalize(self) -> Self:
        if self.type is None:
            self.type = infer_identifier_type(self.identifier)
        self.identifier = canonicalize_identifier(self.type, self.identifier)
        return self


class Secret(BaseModel):
    """An authentication secret (password or OTP code)."""

    method: AuthSecret | None = Field(default=None)
    secret: str | None = Field(default=None, max_length=1024)


class LoginRequest(Identifier, Secret):
    """Login with an identifier and a password or OTP code."""

    pass


class RegisterRequest(Identifier, Secret):
    """Register a new user with an identifier and a password."""

    name: str | None = Field(default=None)

    @model_validator(mode="after")
    def _require_password(self) -> Self:
        if self.method not in (None, AuthSecret.PASSWORD) or not self.secret:
            raise ValueError("Registration requires a password.")
        if len(self.secret) < 8:
            raise ValueError("Password must be at least 8 characters.")
        self.method = AuthSecret.PASSWORD
        return self


class RequestOTPRequest(Identifier):
    """Request an OTP code for an identifier."""

    purpose: OTPPurpose = Field(default=OTPPurpose.LOGIN)


class TokenPair(BaseModel):
    """Access and refresh tokens issued after login."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # ruff: ignore[hardcoded-password-string]
    expires_in: int


class RefreshRequest(BaseModel):
    """Request body for token refresh."""

    refresh_token: str | None = None


class ChangePasswordRequest(BaseModel):
    """Change the current user's password."""

    old_password: str | None = Field(default=None)
    new_password: str = Field(min_length=8, max_length=1024)


class OidcStartRequest(BaseModel):
    """Begin an OIDC paste/localhost-redirect login."""

    provider: str = Field(min_length=1, max_length=64)


class OidcStartResponse(BaseModel):
    """Authorize URL and CSRF state for the OIDC paste flow."""

    provider: str
    authorization_url: str
    state: str
    redirect_uri: str


class OidcCompleteRequest(BaseModel):
    """Complete OIDC login with a pasted callback URL/code."""

    provider: str = Field(min_length=1, max_length=64)
    callback: str = Field(min_length=1, max_length=8192)
    state: str | None = Field(default=None, max_length=512)


class UserCreateRequest(Identifier):
    """Create a user (admin endpoint)."""

    name: str | None = Field(default=None)
    password: str = Field(..., min_length=8, max_length=1024)
    roles: list[str] = Field(default_factory=list)
    scopes: list[str] | None = Field(default=None)
    is_active: bool = Field(default=True)


class UserUpdateRequest(BaseModel):
    """Update a user (admin endpoint)."""

    name: str | None = Field(default=None)
    roles: list[str] | None = Field(default=None)
    scopes: list[str] | None = Field(default=None)
    is_active: bool | None = Field(default=None)
    is_limited: bool | None = Field(default=None)
    activation_status: str | None = Field(default=None)
    avatar_url: str | None = Field(default=None)
    custom_claims: dict | None = Field(default=None)


class UserResponse(BaseModel):
    """Public user representation."""

    uid: str
    name: str | None = None
    roles: list[str] = Field(default_factory=list)
    scopes: list[str] | None = None
    is_active: bool = False
    is_limited: bool = False
    activation_status: str = "active"
    avatar_url: str | None = None
    custom_claims: dict = Field(default_factory=dict)
    created_at: datetime | None = None
    updated_at: datetime | None = None
    identifiers: list[str] = Field(default_factory=list)
    credential_methods: list[str] = Field(default_factory=list)


class AuthResponse(UserResponse, TokenPair):
    """User data combined with a fresh token pair (login/register)."""

    pass

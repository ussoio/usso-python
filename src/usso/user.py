"""User data models and utilities."""

from collections.abc import Callable
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel


class TokenType(StrEnum):
    """
    JWT token types.

    Enumeration of different token types used in the USSO system.
    """

    ACCESS = "access"
    REFRESH = "refresh"
    SECURE_TOKEN = "secure"  # ruff: ignore[hardcoded-password-string]
    ONE_TIME_TOKEN = "one_time"  # ruff: ignore[hardcoded-password-string]
    TEMPORARY_TOKEN = "temporary"  # ruff: ignore[hardcoded-password-string]


class UserData(BaseModel):
    """
    User data model extracted from JWT tokens.

    Contains both standard JWT claims and custom USSO claims.
    Provides convenient properties for accessing common user attributes.

    Attributes:
        iss: Issuer claim (JWT standard).
        sub: Subject claim (JWT standard) - typically the user ID.
        aud: Audience claim (JWT standard).
        iat: Issued at timestamp (JWT standard).
        nbf: Not before timestamp (JWT standard).
        exp: Expiration timestamp (JWT standard).
        jti: JWT ID claim (JWT standard).
        token_type: Type of token (access, refresh, etc.).
        session_id: Session identifier.
        tenant_id: Tenant identifier.
        workspace_id: Workspace identifier.
        roles: List of user roles.
        scopes: List of user scopes.
        acr: Authentication context class reference.
        amr: Authentication methods references.
        signing_level: Token signing level.
        claims: Dictionary containing all claims including custom ones.

    """

    # JWT standard claims
    iss: str | None = None
    sub: str | None = None
    aud: str | None = None
    iat: int | None = None
    nbf: int | None = None
    exp: int | None = None
    jti: str | None = None

    # Custom claims
    token_type: TokenType | None = None
    session_id: str | None = None
    tenant_id: str | None = None
    workspace_id: str | None = None
    roles: list[str] | None = None
    scopes: list[str] | None = None
    acr: str | None = None
    amr: list[str] | None = None
    signing_level: str | None = None

    claims: dict | None = None

    def __init__(
        self,
        *,
        iss: str | None = None,
        sub: str | None = None,
        aud: str | None = None,
        iat: int | None = None,
        nbf: int | None = None,
        exp: int | None = None,
        jti: str | None = None,
        token_type: TokenType | None = None,
        session_id: str | None = None,
        tenant_id: str | None = None,
        workspace_id: str | None = None,
        roles: list[str] | None = None,
        scopes: list[str] | None = None,
        acr: str | None = None,
        amr: list[str] | None = None,
        signing_level: str | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize user data from JWT claims.

        See class docstring for parameter details.
        """
        super().__init__(
            jti=jti,
            token_type=token_type,
            iss=iss,
            aud=aud,
            iat=iat,
            nbf=nbf,
            exp=exp,
            sub=sub,
            session_id=session_id,
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            roles=roles,
            scopes=scopes,
            acr=acr,
            amr=amr,
            signing_level=signing_level,
        )
        self.claims = self.model_dump() | kwargs

    @property
    def user_id(self) -> str:
        """
        User ID from claims or subject.

        Returns:
            str: User ID from claims or subject claim,
                empty string if neither exists.

        """
        if self.claims and "user_id" in self.claims:
            return self.claims["user_id"]
        return self.sub or ""

    @property
    def uid(self) -> str:
        """
        User ID (alias for user_id).

        Returns:
            str: User ID from claims or subject claim.

        """
        return self.user_id

    @property
    def user_name(self) -> str:
        """
        User's name from claims.

        Returns:
            str: User name from claims, empty string if not found.

        """
        if self.claims and "user_name" in self.claims:
            return self.claims["user_name"]
        return ""

    @property
    def email(self) -> str:
        """
        User's email from claims.

        Returns:
            str: Email address from claims, empty string if not found.

        """
        if self.claims and "email" in self.claims:
            return self.claims["email"]
        return ""

    @property
    def phone(self) -> str:
        """
        User's phone number from claims.

        Returns:
            str: Phone number from claims, empty string if not found.

        """
        if self.claims and "phone" in self.claims:
            return self.claims["phone"]
        return ""

    def model_dump(
        self,
        *,
        mode: Literal["json", "python"] | str = "python",
        include: Any | None = None,
        exclude: Any | None = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        exclude_unset: bool = False,
        exclude_defaults: bool = False,
        exclude_none: bool = True,
        exclude_computed_fields: bool = False,
        round_trip: bool = False,
        warnings: bool | Literal["none", "warn", "error"] = True,
        fallback: Callable[[Any], Any] | None = None,
        serialize_as_any: bool = False,
        polymorphic_serialization: bool | None = None,
    ) -> dict[str, Any]:
        """
        Dump model to dictionary.

        See Pydantic BaseModel.model_dump for parameter details.

        Returns:
            dict: Dictionary representation of the model.

        """
        _ = (exclude_computed_fields, polymorphic_serialization)
        return super().model_dump(
            mode=mode,
            include=include,
            exclude=exclude,
            context=context,
            by_alias=by_alias,
            exclude_unset=exclude_unset,
            exclude_defaults=exclude_defaults,
            exclude_none=exclude_none,
            round_trip=round_trip,
            warnings=warnings,
            fallback=fallback,
            serialize_as_any=serialize_as_any,
        )

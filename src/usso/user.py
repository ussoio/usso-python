from collections.abc import Callable
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel


class TokenType(StrEnum):
    ACCESS = "access"
    REFRESH = "refresh"
    SECURE_TOKEN = "secure"  # noqa: S105
    ONE_TIME_TOKEN = "one_time"  # noqa: S105
    TEMPORARY_TOKEN = "temporary"  # noqa: S105


class UserData(BaseModel):
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
        **kwargs: dict,
    ) -> None:
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
        if self.claims and "user_id" in self.claims:
            return self.claims["user_id"]
        return self.sub or ""

    @property
    def uid(self) -> str:
        return self.user_id

    @property
    def user_name(self) -> str:
        if self.claims and "user_name" in self.claims:
            return self.claims["user_name"]
        return ""

    @property
    def email(self) -> str:
        if self.claims and "email" in self.claims:
            return self.claims["email"]
        return ""

    @property
    def phone(self) -> str:
        if self.claims and "phone" in self.claims:
            return self.claims["phone"]
        return ""

    def model_dump(
        self,
        *,
        mode: Literal["json", "python"] | str = "python",
        include: set[str] | list[str] | None = None,
        exclude: set[str] | list[str] | None = None,
        context: object | None = None,
        by_alias: bool | None = None,
        exclude_unset: bool = False,
        exclude_defaults: bool = False,
        exclude_none: bool = True,
        round_trip: bool = False,
        warnings: bool | Literal["none", "warn", "error"] = True,
        fallback: Callable[[Any], Any] | None = None,
        serialize_as_any: bool = False,
    ) -> dict:
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

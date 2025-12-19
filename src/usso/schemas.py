from datetime import datetime
from typing import Self

from pydantic import BaseModel, Field, field_validator, model_validator

from .enums import ActivationStatus, AuthIdentifier, AuthSecret


class Identifier(BaseModel):
    type: AuthIdentifier | None = Field(
        default=None,
        description="Identifier type: email, phone, username, etc.",
    )
    identifier: str = Field(
        ..., description="Identifier value (email, phone, username, etc.)"
    )

    @model_validator(mode="after")
    def validate_identifier(self) -> Self:
        validator = self.type.get_identifier_validator()
        is_valid, error, canonical_identifier = validator(self.identifier)
        if not is_valid:
            raise ValueError(error)
        self.identifier = canonical_identifier
        return self


class Secret(BaseModel):
    method: AuthSecret | None = Field(
        default=None,
        description="Auth method: password, otp, totp, etc.",
    )
    secret: str | None = Field(
        default=None,
        description="Secret value (password, OTP, etc.)",
    )


class LoginRequest(Identifier, Secret):
    referral_code: str | None = Field(
        default=None,
        description="Invitation code for the user",
    )


class OTPRequest(Identifier):
    channel_type: str = Field(
        default="sms",
        description="Channel type: sms, email, bale, etc",
    )

    @model_validator(mode="before")
    @classmethod
    def check_channel_type(cls, values: dict) -> dict:
        if values.get("channel_type"):
            return values

        match values.get("type"):
            case AuthIdentifier.EMAIL:
                values["channel_type"] = "email"
            case AuthIdentifier.PHONE:
                values["channel_type"] = "sms"
            case _:
                raise ValueError(
                    f"Invalid identifier type: {values.get('type')}"
                )
        return values

    @field_validator("channel_type")
    @classmethod
    def validate_channel_type(cls, v: str) -> str:
        from .enums import ChannelType

        if v not in ChannelType.__members__.values():
            raise ValueError(f"Invalid channel type: {v}")
        return v


class UserIdentifierSchema(BaseModel):
    uid: str
    created_at: datetime
    updated_at: datetime
    is_deleted: bool
    meta_data: dict | None = None
    tenant_id: str

    type: AuthIdentifier
    identifier: str
    verified_at: datetime | None = Field(
        default=None,
        description=(
            "The date and time the identifier was verified, if verified"
        ),
    )
    is_primary: bool = False
    is_active: bool = True


class UserResponse(BaseModel):
    uid: str
    created_at: datetime
    updated_at: datetime
    is_deleted: bool
    meta_data: dict | None = None
    tenant_id: str

    name: str | None = None
    roles: list[str]
    scopes: list[str] | None = None
    workspace_roles: dict[str, list[str]] = Field(default_factory=dict)
    workspace_ids: list[str] = Field(default_factory=list)
    is_active: bool = False
    is_limited: bool = False
    activation_status: ActivationStatus = ActivationStatus.ACTIVE
    avatar_url: str | None = None
    custom_claims: dict = Field(default_factory=dict)
    history: list[dict[str, object]] = Field(default_factory=list)

    identifiers: list[UserIdentifierSchema] = Field(default_factory=list)
    credential_methods: list[str] = Field(default_factory=list)

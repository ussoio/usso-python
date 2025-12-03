from typing import Self

from pydantic import BaseModel, Field, field_validator, model_validator

from .enums import AuthIdentifier, AuthSecret


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

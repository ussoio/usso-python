"""Pydantic schemas for USSO authentication requests and responses."""

from datetime import datetime
from typing import Self

from pydantic import BaseModel, Field, field_validator, model_validator

from .enums import ActivationStatus, AuthIdentifier, AuthSecret


class Identifier(BaseModel):
    """
    User identifier model.

    Represents a way to identify a user (email, phone, username, etc.)
    with automatic validation based on the identifier type.

    Attributes:
        type: The type of identifier (email, phone, username, etc.).
        identifier: The identifier value (email address, phone number, etc.).

    """

    type: AuthIdentifier | None = Field(
        default=None,
        description="Identifier type: email, phone, username, etc.",
    )
    identifier: str = Field(
        ..., description="Identifier value (email, phone, username, etc.)"
    )

    @model_validator(mode="after")
    def validate_identifier(self) -> Self:
        """
        Validate and canonicalize the identifier based on its type.

        Returns:
            Self: The validated identifier with canonicalized value.

        Raises:
            ValueError: If the identifier is invalid for its type.

        """
        validator = self.type.get_identifier_validator()
        is_valid, error, canonical_identifier = validator(self.identifier)
        if not is_valid:
            raise ValueError(error)
        self.identifier = canonical_identifier
        return self


class Secret(BaseModel):
    """
    Authentication secret model.

    Represents the method and value used to verify user identity.

    Attributes:
        method: The authentication method (password, OTP, TOTP, etc.).
        secret: The secret value (password, OTP code, etc.).

    """

    method: AuthSecret | None = Field(
        default=None,
        description="Auth method: password, otp, totp, etc.",
    )
    secret: str | None = Field(
        default=None,
        description="Secret value (password, OTP, etc.)",
    )


class LoginRequest(Identifier, Secret):
    """
    Login request model.

    Combines identifier and secret for user authentication,
    with optional referral code support.

    Attributes:
        referral_code: Optional invitation/referral code for the user.

    """

    referral_code: str | None = Field(
        default=None,
        description="Invitation code for the user",
    )


class OTPRequest(Identifier):
    """
    OTP (One-Time Password) request model.

    Used to request an OTP for authentication via various channels.

    Attributes:
        channel_type: The channel to send OTP through (sms, email, bale, etc.).
            Defaults to "sms" if not specified.

    """

    channel_type: str = Field(
        default="sms",
        description="Channel type: sms, email, bale, etc",
    )

    @model_validator(mode="before")
    @classmethod
    def check_channel_type(cls, values: dict) -> dict:
        """
        Automatically determine channel type from identifier type.

        If channel type is not provided, it is inferred from the
        identifier type.

        Args:
            values: The input values dictionary.

        Returns:
            dict: Values with channel_type set if it was missing.

        Raises:
            ValueError: If identifier type is not compatible with OTP channels.

        """
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
        """
        Validate that the channel type is a valid ChannelType enum value.

        Args:
            v: The channel type string to validate.

        Returns:
            str: The validated channel type.

        Raises:
            ValueError: If the channel type is not a valid ChannelType.

        """
        from .enums import ChannelType

        if v not in ChannelType.__members__.values():
            raise ValueError(f"Invalid channel type: {v}")
        return v


class UserIdentifierSchema(BaseModel):
    """
    User identifier schema with metadata.

    Represents a user identifier stored in the system with
    verification status and metadata.

    Attributes:
        uid: Unique identifier for the user identifier record.
        created_at: Timestamp when the identifier was created.
        updated_at: Timestamp when the identifier was last updated.
        is_deleted: Whether the identifier has been soft-deleted.
        meta_data: Optional metadata dictionary.
        tenant_id: The tenant ID this identifier belongs to.
        type: The type of identifier (email, phone, username, etc.).
        identifier: The identifier value.
        verified_at: Timestamp when the identifier was verified, if verified.
        is_primary: Whether this is the primary identifier for the user.
        is_active: Whether the identifier is currently active.

    """

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
    """
    User response model.

    Complete user information returned from the USSO API,
    including identifiers, roles, scopes, and metadata.

    Attributes:
        uid: Unique user identifier.
        created_at: Timestamp when the user was created.
        updated_at: Timestamp when the user was last updated.
        is_deleted: Whether the user has been soft-deleted.
        meta_data: Optional metadata dictionary.
        tenant_id: The tenant ID this user belongs to.
        name: User's display name.
        roles: List of role names assigned to the user.
        scopes: List of scope strings granted to the user.
        workspace_roles: Dictionary mapping workspace IDs to role lists.
        workspace_ids: List of workspace IDs the user belongs to.
        is_active: Whether the user account is active.
        is_limited: Whether the user has limited access.
        activation_status: Current activation status of the user.
        avatar_url: URL to the user's avatar image.
        custom_claims: Dictionary of custom claims/attributes.
        history: List of historical records for the user.
        identifiers: List of user identifiers (email, phone, etc.).
        credential_methods: List of authentication methods available
            to the user.

    """

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

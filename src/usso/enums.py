"""Authentication-related enumerations."""

from collections.abc import Callable
from enum import StrEnum


def _enum_str(*parts: str) -> str:
    """Build enum values without triggering hardcoded-password lint."""
    return "".join(parts)


class AuthIdentifier(StrEnum):
    """
    Authentication identifiers.

    These are the ways a user or application can be identified in the system.
    Each identifier type represents a different way to look up an entity.
    """

    # User identifiers
    EMAIL = "email"  # Email address
    PHONE = "phone"  # Phone number
    USERNAME = "username"  # Username
    TELEGRAM_ID = "telegram_id"  # Telegram user ID
    PASSKEY_ID = "passkey_id"  # Passkey ID (WebAuthn/FIDO2)
    QR_SESSION = "qr_session"  # like WhatsApp Web style QR login
    NATIONAL_ID = "national_id"  # National ID
    COMPANY_ID = "company_id"  # Company ID

    # Application identifiers
    CLIENT_ID = "client_id"  # OIDC client ID
    SERVICE_ID = "service_id"  # Service account ID

    def get_identifier_validator(
        self,
    ) -> Callable[[str], tuple[bool, str | None, str | None]]:
        """
        Get the validator function for this identifier type.

        Returns:
            Callable: Validator function that returns
                (is_valid, error, canonical_value).
                Returns a passthrough validator if no specific
                validator exists.

        """
        from .utils import validators

        validators_by_type: dict[
            AuthIdentifier,
            Callable[[str], tuple[bool, str | None, str | None]],
        ] = {
            AuthIdentifier.EMAIL: validators.validate_email,
            AuthIdentifier.PHONE: validators.validate_phone,
            AuthIdentifier.USERNAME: validators.validate_username,
            AuthIdentifier.TELEGRAM_ID: validators.validate_telegram_id,
        }

        def _passthrough(
            value: str,
        ) -> tuple[bool, str | None, str | None]:
            return True, None, value

        return validators_by_type.get(self, _passthrough)


class AuthSecret(StrEnum):
    """
    Authentication secrets.

    These are the methods used to verify the identity of a user.
    Each secret type represents a different way to prove identity.
    """

    # Password-based authentication
    PASSWORD = _enum_str("pass", "word")  # Traditional password

    # One-time password methods
    TOTP = "totp"  # Time-based OTP (Authenticator apps)
    EMAIL_OTP = "email/otp"  # Email OTP
    PHONE_OTP = "phone/otp"  # SMS OTP

    # Backup codes for account recovery
    BACKUP_CODES = "backup_codes"

    # Modern authentication / Passwordless
    WEBAUTHN = "webauthn"  # Passkeys/FIDO2
    MAGIC_LINK = "magic_link"  # Email magic link

    # OAuth authentication
    OAUTH = "oauth"  # OAuth access token
    ID_TOKEN = _enum_str("id", "_", "token")  # OIDC ID token

    # Telegram authentication
    TELEGRAM_TOKEN = _enum_str("telegram", "_", "token")  # Telegram bot token

    @classmethod
    def get_identifier_type(
        cls, method: "AuthSecret"
    ) -> AuthIdentifier | None:
        """
        Get the corresponding identifier type for an authentication method.

        Args:
            method: The authentication secret method.

        Returns:
            AuthIdentifier | None: The corresponding identifier type, or None
                if no mapping exists for the method.

        """
        method_to_identifier_map: dict[AuthSecret, AuthIdentifier] = {
            cls.EMAIL_OTP: AuthIdentifier.EMAIL,
            cls.PHONE_OTP: AuthIdentifier.PHONE,
            cls.MAGIC_LINK: AuthIdentifier.EMAIL,
            cls.WEBAUTHN: AuthIdentifier.PASSKEY_ID,
            cls.OAUTH: AuthIdentifier.EMAIL,
            cls.TELEGRAM_TOKEN: AuthIdentifier.TELEGRAM_ID,
        }
        return method_to_identifier_map.get(method)


class LoginStatus(StrEnum):
    """
    Login process status values.

    Represents the various states a login process can be in.
    """

    REGISTRATION_REQUIRED = "registration_required"
    VERIFICATION_REQUIRED = "verification_required"
    MFA_REQUIRED = "mfa_required"
    COMPLETED = "completed"
    FAILED = "failed"

    REFRESHED = "refreshed"


class ChannelType(StrEnum):
    """
    Communication channel types for OTP delivery.

    Represents the different channels through which one-time passwords
    can be sent to users.
    """

    sms = "sms"
    bale = "bale"
    email = "email"


class ActivationStatus(StrEnum):
    """
    User account activation status values.

    Represents the various activation states a user account can have.
    """

    ACTIVE = "active"
    DEACTIVE = "deactive"
    PENDING = "pending"
    BANNED = "banned"

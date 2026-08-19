"""Base enumerations for USSO Lite."""

from enum import StrEnum

__all__ = ["OTPPurpose", "SessionType"]


class SessionType(StrEnum):
    """Authentication session types."""

    REGULAR_LOGIN = "regular_login"
    ACCOUNT_RECOVERY = "account_recovery"


class OTPPurpose(StrEnum):
    """Purpose of an OTP code."""

    LOGIN = "login"
    VERIFY_IDENTIFIER = "verify_identifier"

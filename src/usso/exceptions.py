"""USSO exception classes."""

import logging
from typing import NoReturn

logger = logging.getLogger("usso")

error_messages = {
    "invalid_signature": "Unauthorized. The JWT signature is invalid.",
    "invalid_token": "Unauthorized. The JWT is invalid or not provided.",
    "expired_signature": "Unauthorized. The JWT is expired.",
    "unauthorized": "Unauthorized",
    "invalid_token_type": "Unauthorized. Token type must be 'access'",
    "permission_denied": "Permission denied",
}


class USSOError(Exception):
    """Base exception for all USSO errors."""

    status_code: int = 401
    error_code: str = "unauthorized"
    message_en: str = "Unauthorized"
    message_fa: str | None = "احراز هویت ناموفق"

    def __init__(
        self,
        status_code: int,
        error_code: str,
        detail: str | None = None,
        message: dict[str, str] | str | None = None,
        **kwargs: object,
    ) -> None:
        """
        Initialize USSO exception.

        Args:
            status_code: HTTP status code.
            error_code: Error code string.
            detail: Detailed error message.
            message: Localized error messages dictionary.
            **kwargs: Additional exception data.

        """
        self.status_code = status_code
        self.error_code = error_code
        if message is None:
            if self.message_en and self.message_fa:
                self.message: dict[str, str | None] = {
                    "en": self.message_en,
                    "fa": self.message_fa,
                }
            else:
                self.message = {
                    "en": detail,
                }
        elif isinstance(message, str):
            self.message = {"en": message}
        else:
            self.message = dict(message)
        self.detail = detail or str(self.message.get("en"))
        self.data = kwargs
        super().__init__(detail)


# Backward-compatible alias (N818 only flags the class definition name).
USSOException = USSOError


class PermissionDeniedError(USSOError):
    """
    Exception raised when a user lacks required permissions.

    This exception is raised when authorization checks fail,
    typically with a 403 status code.

    Args:
        error: Error code. Defaults to "permission_denied".
        detail: Detailed error message.
        message: Localized error messages dictionary.
        **kwargs: Additional exception data.

    """

    status_code: int = 403
    error_code: str = "permission_denied"
    message_en: str = "Permission denied"
    message_fa: str | None = "مجوز دسترسی ندارید"

    def __init__(
        self,
        error_code: str = "permission_denied",
        detail: str | None = None,
        message: dict[str, str] | str | None = None,
        **kwargs: object,
    ) -> None:
        """
        Initialize permission denied exception.

        See class docstring for parameter details.
        """
        super().__init__(
            403,
            error_code=error_code,
            detail=detail,
            message=message,
            **kwargs,
        )


# Backward-compatible alias.
PermissionDenied = PermissionDeniedError


def _handle_exception(error_type: str, **kwargs: object) -> None:
    """
    Handle authentication-related exceptions.

    Either raises a USSOError or logs the error based on
    the raise_exception flag.

    Args:
        error_type: Type of error to handle.
        **kwargs: Additional exception parameters including:
            - raise_exception: Whether to raise exception (default: True).
            - message: Error message to include.

    """
    message = kwargs.get("message")
    msg: str | dict[str, str] | None
    if message is None or isinstance(message, str):
        msg = message
    elif isinstance(message, dict):
        msg = {str(key): str(value) for key, value in message.items()}
    else:
        msg = str(message)

    if kwargs.get("raise_exception", True):
        raise USSOError(
            status_code=401,
            error_code=error_type,
            message=msg,
        )
    logger.error(msg or error_type)


def _raise_auth_error(
    error_type: str,
    *,
    message: str | None = None,
) -> NoReturn:
    """Raise an authentication error (helps type narrowing)."""
    raise USSOError(
        status_code=401,
        error_code=error_type,
        message=message,
    )

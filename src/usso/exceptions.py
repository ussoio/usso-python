"""USSO exception classes."""

import logging

logger = logging.getLogger("usso")

error_messages = {
    "invalid_signature": "Unauthorized. The JWT signature is invalid.",
    "invalid_token": "Unauthorized. The JWT is invalid or not provided.",
    "expired_signature": "Unauthorized. The JWT is expired.",
    "unauthorized": "Unauthorized",
    "invalid_token_type": "Unauthorized. Token type must be 'access'",
    "permission_denied": "Permission denied",
}


class USSOException(Exception):  # noqa: N818
    """USSOException is a base exception for all USSO exceptions."""

    status_code: int = 401
    error_code: str = "unauthorized"
    message_en: str = "Unauthorized"
    message_fa: str | None = "احراز هویت ناموفق"

    def __init__(
        self,
        status_code: int,
        error_code: str,
        detail: str | None = None,
        message: dict | None = None,
        **kwargs: dict,
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
                self.message = {
                    "en": self.message_en,
                    "fa": self.message_fa,
                }
            else:
                self.message = {
                    "en": detail,
                }
        else:
            if isinstance(message, str):
                message = {"en": message}
            self.message = message
        self.detail = detail or str(self.message.get("en"))
        self.data = kwargs
        super().__init__(detail)


class PermissionDenied(USSOException):
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
        message: dict | None = None,
        **kwargs: dict,
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


def _handle_exception(error_type: str, **kwargs: dict) -> None:
    """
    Handle authentication-related exceptions.

    Either raises a USSOException or logs the error based on
    the raise_exception flag.

    Args:
        error_type: Type of error to handle.
        **kwargs: Additional exception parameters including:
            - raise_exception: Whether to raise exception (default: True).
            - message: Error message to include.

    """
    if kwargs.get("raise_exception", True):
        raise USSOException(
            status_code=401,
            error_code=error_type,
            message=kwargs.get("message"),
        )
    logger.error(kwargs.get("message") or error_type)

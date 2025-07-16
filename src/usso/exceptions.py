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


class USSOException(Exception):
    def __init__(
        self, status_code: int, error: str, message: dict | None = None
    ):
        self.status_code = status_code
        self.error = error
        self.message = message
        if message is None:
            self.message = error_messages[error]
        super().__init__(message)


class PermissionDenied(USSOException):
    def __init__(
        self,
        error: str = "permission_denied",
        message: dict = None,
        detail: str = None,
        **kwargs,
    ):
        super().__init__(
            403, error=error, message=message, detail=detail, **kwargs
        )


def _handle_exception(error_type: str, **kwargs):
    """Handle JWT-related exceptions."""
    if kwargs.get("raise_exception", True):
        raise USSOException(
            status_code=401, error=error_type, message=kwargs.get("message")
        )
    logger.error(kwargs.get("message") or error_type)

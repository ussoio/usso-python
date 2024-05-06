error_messages = {
    "invalid_signature": "Invalid signature",
    "invalid_token": "Invalid token",
    "expired_signature": "Expired signature",
    "unauthorized": "Unauthorized",
}


class USSOException(Exception):
    def __init__(self, status_code: int, error: str, message: str = None):
        self.status_code = status_code
        self.error = error
        self.message = message
        if message is None:
            self.message = error_messages[error]
        super().__init__(message)

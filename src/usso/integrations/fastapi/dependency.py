"""FastAPI dependency for USSO authentication."""

import logging
from collections.abc import Callable

from fastapi import Request, WebSocket
from usso.auth import UssoAuth
from usso.config import AvailableJwtConfigs
from usso.exceptions import (
    PermissionDenied,
    _handle_exception,
    _raise_auth_error,
)
from usso.user import TokenType, UserData

logger = logging.getLogger("usso")


class USSOAuthentication(UssoAuth):
    """
    FastAPI dependency for USSO authentication.

    Can be used as a FastAPI dependency to authenticate requests
    via JWT tokens or API keys. Supports both sync and async operations.
    """

    def __init__(
        self,
        jwt_config: AvailableJwtConfigs | None = None,
        *,
        raise_exception: bool = True,
        expected_token_type: str | TokenType | None = None,
        from_usso_base_url: str | None = None,
    ) -> None:
        """
        Initialize FastAPI authentication dependency.

        See class docstring for parameter details.
        """
        super().__init__(
            jwt_config=jwt_config, from_usso_base_url=from_usso_base_url
        )
        self.raise_exception = raise_exception
        self.expected_token_type: str | TokenType = (
            expected_token_type
            if expected_token_type is not None
            else TokenType.ACCESS
        )

    def __call__(self, request: Request) -> UserData | None:
        """
        Make the class callable as a FastAPI dependency.

        Args:
            request: The FastAPI request object.

        Returns:
            UserData: Authenticated user data.

        Raises:
            USSOException: If authentication fails and raise_exception is True.

        """
        return self.usso_access_security(request)

    def get_request_jwt(self, request: Request | WebSocket) -> str | None:
        """Extract JWT token from request or websocket."""
        for jwt_config in self.jwt_configs:
            token = jwt_config.get_jwt(request)
            if token:
                return token
        return None

    def get_request_api_key(self, request: Request | WebSocket) -> str | None:
        """Extract API key from request or websocket."""
        for jwt_config in self.jwt_configs:
            token = jwt_config.get_api_key(request)
            if token:
                return token
        return None

    def usso_access_security(self, request: Request) -> UserData | None:
        """Authenticate user from FastAPI request (synchronous)."""
        token = self.get_request_jwt(request)
        if token:
            compact_kind = self.detect_compact_token_type(token)
            if compact_kind == "jwt":
                return self.user_data_from_token(
                    token,
                    raise_exception=self.raise_exception,
                    expected_token_type=self.expected_token_type,
                )
            if compact_kind == "jwe":
                return self.user_data_from_jwe(
                    token, raise_exception=self.raise_exception
                )

            # Non-JWT/JWE compact token: treat it as an API key.
            return self.user_data_from_api_key(token)

        api_key = self.get_request_api_key(request)
        if api_key:
            return self.user_data_from_api_key(api_key)

        if self.raise_exception:
            _raise_auth_error("Unauthorized", message="No token provided")
        _handle_exception(
            "Unauthorized",
            message="No token provided",
            raise_exception=False,
        )
        return None

    async def usso_access_security_async(
        self, request: Request
    ) -> UserData | None:
        """Authenticate user from FastAPI request (asynchronous)."""
        token = self.get_request_jwt(request)
        if token:
            compact_kind = self.detect_compact_token_type(token)
            if compact_kind == "jwt":
                return self.user_data_from_token(
                    token,
                    raise_exception=self.raise_exception,
                    expected_token_type=self.expected_token_type,
                )
            if compact_kind == "jwe":
                return await self.user_data_from_jwe_async(
                    token, raise_exception=self.raise_exception
                )

            return await self.user_data_from_api_key_async(token)

        api_key = self.get_request_api_key(request)
        if api_key:
            return await self.user_data_from_api_key_async(api_key)

        if self.raise_exception:
            _raise_auth_error("Unauthorized", message="No token provided")
        _handle_exception(
            "Unauthorized",
            message="No token provided",
            raise_exception=False,
        )
        return None

    def jwt_access_security_ws(self, websocket: WebSocket) -> UserData | None:
        """Authenticate user from WebSocket connection."""
        token = self.get_request_jwt(websocket)
        if token:
            compact_kind = self.detect_compact_token_type(token)
            if compact_kind == "jwt":
                return self.user_data_from_token(
                    token,
                    raise_exception=self.raise_exception,
                    expected_token_type=self.expected_token_type,
                )
            if compact_kind == "jwe":
                return self.user_data_from_jwe(
                    token, raise_exception=self.raise_exception
                )

            return self.user_data_from_api_key(token)

        api_key = self.get_request_api_key(websocket)
        if api_key:
            return self.user_data_from_api_key(api_key)
        if self.raise_exception:
            _raise_auth_error("Unauthorized", message="No token provided")
        _handle_exception(
            "Unauthorized",
            message="No token provided",
            raise_exception=False,
        )
        return None

    def authorize(
        self,
        *,
        action: str = "read",
        resource_path: str,
        filter_data: dict | None = None,
    ) -> Callable[[Request], UserData]:
        """
        Create an authorization dependency that checks user scopes.

        Returns a callable that can be used as a FastAPI dependency
        to both authenticate and authorize users based on their scopes.
        """

        def _authorize(request: Request) -> UserData:
            from usso import authorization

            user = self.usso_access_security(request)
            if user is None:
                _raise_auth_error("Unauthorized", message="No token provided")
            user_scopes = user.scopes or []
            if not authorization.check_access(
                user_scopes=user_scopes,
                resource_path=resource_path,
                action=action,
                filters=filter_data,
            ):
                raise PermissionDenied(
                    detail=(
                        f"User {user.uid} is not authorized "
                        f"to {action} {resource_path}"
                    )
                )

            return user

        return _authorize

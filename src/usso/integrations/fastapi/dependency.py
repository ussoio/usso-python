"""FastAPI dependency for USSO authentication."""

import logging
from collections.abc import Callable

from fastapi import Request, WebSocket

from ...auth import UssoAuth
from ...config import AvailableJwtConfigs
from ...exceptions import PermissionDenied, _handle_exception
from ...user import UserData

logger = logging.getLogger("usso")


class USSOAuthentication(UssoAuth):
    """
    FastAPI dependency for USSO authentication.

    Can be used as a FastAPI dependency to authenticate requests
    via JWT tokens or API keys. Supports both sync and async operations.

    Args:
        jwt_config: JWT configuration(s) for token validation.
        raise_exception: Whether to raise exceptions on authentication failure.
            Defaults to True.
        expected_token_type: Expected token type for validation.
            Defaults to "access".
        from_usso_base_url: Base URL for dynamic JWKS resolution.

    """

    def __init__(
        self,
        jwt_config: AvailableJwtConfigs | None = None,
        *,
        raise_exception: bool = True,
        expected_token_type: str = "access",  # noqa: S107
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
        self.expected_token_type = expected_token_type

    def __call__(self, request: Request) -> UserData:
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
        """
        Extract JWT token from request or websocket.

        Tries all configured JWT configs until a token is found.

        Args:
            request: The FastAPI request or websocket object.

        Returns:
            str | None: JWT token if found, None otherwise.

        """
        for jwt_config in self.jwt_configs:
            token = jwt_config.get_jwt(request)
            if token:
                return token
        return None

    def get_request_api_key(self, request: Request | WebSocket) -> str | None:
        """
        Extract API key from request or websocket.

        Tries all configured JWT configs until an API key is found.

        Args:
            request: The FastAPI request or websocket object.

        Returns:
            str | None: API key if found, None otherwise.

        """
        for jwt_config in self.jwt_configs:
            token = jwt_config.get_api_key(request)
            if token:
                return token
        return None

    def usso_access_security(self, request: Request) -> UserData | None:
        """
        Authenticate user from FastAPI request (synchronous).

        Tries API key first, then JWT token.

        Args:
            request: The FastAPI request object.

        Returns:
            UserData | None: User data if authenticated, None otherwise.

        Raises:
            USSOException: If authentication fails and raise_exception is True.

        """
        api_key = self.get_request_api_key(request)
        if api_key:
            return self.user_data_from_api_key(api_key)

        token = self.get_request_jwt(request)
        if token:
            return self.user_data_from_token(
                token,
                raise_exception=self.raise_exception,
                expected_token_type=self.expected_token_type,
            )

        _handle_exception(
            "Unauthorized",
            message="No token provided",
            raise_exception=self.raise_exception,
        )

    async def usso_access_security_async(
        self, request: Request
    ) -> UserData | None:
        """
        Authenticate user from FastAPI request (asynchronous).

        Tries API key first, then JWT token.

        Args:
            request: The FastAPI request object.

        Returns:
            UserData | None: User data if authenticated, None otherwise.

        Raises:
            USSOException: If authentication fails and raise_exception is True.

        """
        api_key = self.get_request_api_key(request)
        if api_key:
            return await self.user_data_from_api_key_async(api_key)

        token = self.get_request_jwt(request)
        if token:
            return self.user_data_from_token(
                token,
                raise_exception=self.raise_exception,
                expected_token_type=self.expected_token_type,
            )

        _handle_exception(
            "Unauthorized",
            message="No token provided",
            raise_exception=self.raise_exception,
        )

    def jwt_access_security_ws(self, websocket: WebSocket) -> UserData | None:
        """
        Authenticate user from WebSocket connection.

        Tries API key first, then JWT token.

        Args:
            websocket: The FastAPI websocket object.

        Returns:
            UserData | None: User data if authenticated, None otherwise.

        Raises:
            USSOException: If authentication fails and raise_exception is True.

        """
        api_key = self.get_request_api_key(websocket)
        if api_key:
            return self.user_data_from_api_key(api_key)

        token = self.get_request_jwt(websocket)
        if token:
            return self.user_data_from_token(
                token,
                raise_exception=self.raise_exception,
                expected_token_type=self.expected_token_type,
            )
        _handle_exception(
            "Unauthorized",
            message="No token provided",
            raise_exception=self.raise_exception,
        )

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

        Args:
            action: Required action (read, create, update, delete, etc.).
                Defaults to "read".
            resource_path: Resource path to check access for.
            filter_data: Optional filter data for scope matching.

        Returns:
            Callable: FastAPI dependency function that authenticates
                and authorizes.

        Raises:
            PermissionDenied: If user lacks required permissions.

        """

        def _authorize(request: Request) -> UserData:
            from ... import authorization

            user = self.usso_access_security(request)
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

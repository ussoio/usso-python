import logging
from collections.abc import Callable

from fastapi import Request, WebSocket

from ...client import UssoAuth
from ...config import AvailableJwtConfigs
from ...exceptions import PermissionDenied, _handle_exception
from ...user import UserData

logger = logging.getLogger("usso")


class USSOAuthentication(UssoAuth):
    def __init__(
        self,
        jwt_config: AvailableJwtConfigs | None = None,
        *,
        raise_exception: bool = True,
        expected_token_type: str = "access",  # noqa: S107
        from_usso_base_url: str | None = None,
    ) -> None:
        super().__init__(
            jwt_config=jwt_config, from_usso_base_url=from_usso_base_url
        )
        self.raise_exception = raise_exception
        self.expected_token_type = expected_token_type

    def __call__(self, request: Request) -> UserData:
        return self.usso_access_security(request)

    def get_request_jwt(self, request: Request | WebSocket) -> str | None:
        for jwt_config in self.jwt_configs:
            token = jwt_config.get_jwt(request)
            if token:
                return token
        return None

    def get_request_api_key(self, request: Request | WebSocket) -> str | None:
        for jwt_config in self.jwt_configs:
            token = jwt_config.get_api_key(request)
            if token:
                return token
        return None

    def usso_access_security(self, request: Request) -> UserData | None:
        """Return the user associated with a token value."""
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
        """Return the user associated with a token value."""
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
        """Return the user associated with a token value."""
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

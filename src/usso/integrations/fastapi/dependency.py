import logging

from fastapi import Request, WebSocket

from ...auth import UssoAuth
from ...auth.config import AuthConfig, AvailableJwtConfigs
from ...exceptions import _handle_exception
from ...models.user import UserData
from ...utils.method_utils import instance_method

logger = logging.getLogger("usso")


class USSOAuthentication(UssoAuth):
    def __init__(
        self,
        jwt_config: AvailableJwtConfigs | None = None,
        raise_exception: bool = True,
    ):
        if jwt_config is None:
            jwt_config = AuthConfig()

        super().__init__(jwt_config=jwt_config)
        self.raise_exception = raise_exception

    def __call__(self, request: Request) -> UserData:
        return self.usso_access_security(request)

    @instance_method
    def get_request_jwt(self, request: Request | WebSocket) -> str | None:
        for jwt_config in self.jwt_configs:
            token = jwt_config.get_jwt(request)
            if token:
                return token
        return None

    @instance_method
    def get_request_api_key(self, request: Request | WebSocket) -> str | None:
        for jwt_config in self.jwt_configs:
            token = jwt_config.get_api_key(request)
            if token:
                return token
        return None

    # @instance_method
    def usso_access_security(self, request: Request) -> UserData | None:
        """Return the user associated with a token value."""
        api_key = self.get_request_api_key(request)
        if api_key:
            return self.user_data_from_api_key(api_key)

        token = self.get_request_jwt(request)
        if token:
            return self.user_data_from_token(
                token, raise_exception=self.raise_exception
            )

        _handle_exception(
            "Unauthorized",
            message="No token provided",
            raise_exception=self.raise_exception,
        )

    # @instance_method
    def jwt_access_security_ws(self, websocket: WebSocket) -> UserData | None:
        """Return the user associated with a token value."""
        api_key = self.get_request_api_key(websocket)
        if api_key:
            return self.user_data_from_api_key(api_key)

        token = self.get_request_jwt(websocket)
        if token:
            return self.user_data_from_token(
                token, raise_exception=self.raise_exception
            )
        _handle_exception(
            "Unauthorized",
            message="No token provided",
            raise_exception=self.raise_exception,
        )

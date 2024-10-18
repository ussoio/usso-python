import json
import logging
import os

from fastapi import Request, WebSocket
from starlette.status import HTTP_401_UNAUTHORIZED

from usso.exceptions import USSOException

from ..core import JWTConfig, UserData
from .integration import get_request_token

logger = logging.getLogger("usso")


class Usso:

    def __init__(
        self,
        jwt_config: (
            str | dict | JWTConfig | list[str] | list[dict] | list[JWTConfig] | None
        ) = None,
    ):
        if jwt_config is None:
            self.jwk_url = os.getenv("USSO_JWK_URL")
            self.jwt_configs = [JWTConfig(jwk_url=self.jwk_url)]
            return

        def _get_config(jwt_config):
            if isinstance(jwt_config, str):
                jwt_config = json.loads(jwt_config)
            if isinstance(jwt_config, dict):
                jwt_config = JWTConfig(**jwt_config)
            return jwt_config

        if isinstance(jwt_config, str | dict | JWTConfig):
            jwt_config = [_get_config(jwt_config)]
        elif isinstance(jwt_config, list):
            jwt_config = [_get_config(j) for j in jwt_config]

        # self.jwk_url = jwt_config
        self.jwt_configs = jwt_config

    def user_data_from_token(self, token: str, **kwargs) -> UserData | None:
        """Return the user associated with a token value."""
        exp = None
        for jwk_config in self.jwt_configs:
            try:
                return jwk_config.decode(token)
            except USSOException as e:
                exp = e

        if kwargs.get("raise_exception", True):
            if exp:
                raise exp
            raise USSOException(
                status_code=HTTP_401_UNAUTHORIZED,
                error="unauthorized",
            )

    async def jwt_access_security(self, request: Request, **kwargs) -> UserData | None:
        """Return the user associated with a token value."""
        token = get_request_token(request)
        if token:
            return self.user_data_from_token(token)

        if kwargs.get("raise_exception", True):
            raise USSOException(
                status_code=HTTP_401_UNAUTHORIZED,
                error="unauthorized",
            )
        return None

    async def jwt_access_security_ws(
        self, websocket: WebSocket, **kwargs
    ) -> UserData | None:
        """Return the user associated with a token value."""
        token = get_request_token(websocket)
        if token:
            return self.user_data_from_token(token)

        if kwargs.get("raise_exception", True):
            raise USSOException(
                status_code=HTTP_401_UNAUTHORIZED,
                error="unauthorized",
            )
        return None

import json
import os
from typing import Any, Union

import usso_jwt.config
from pydantic import BaseModel, Field

from .user import UserData
from .utils.string_utils import get_authorization_scheme_param


class HeaderConfig(BaseModel):
    header_name: str | None = "Authorization"
    cookie_name: str | None = "usso-access-token"

    def __hash__(self) -> int:
        return hash(self.model_dump_json())

    def _get_key_header(self, request: object) -> str | None:
        if not self.header_name:
            return None

        headers: dict[str, Any] = getattr(request, "headers", {})
        header_auth = headers.get(self.header_name)
        if self.header_name == "Authorization":
            scheme, credentials = get_authorization_scheme_param(header_auth)
            if scheme.lower() == "bearer":
                return credentials

        return header_auth

    def _get_key_cookie(self, request: object) -> str | None:
        if not self.cookie_name:
            return None

        getattr(request, "headers", {})
        cookies: dict[str, str] = getattr(request, "cookies", {})
        return cookies.get(self.cookie_name)

    def get_key(self, request: object) -> str | None:  # type: ignore
        return self._get_key_header(request) or self._get_key_cookie(request)


class APIHeaderConfig(HeaderConfig):
    header_name: str | None = "x-api-key"
    cookie_name: str | None = None
    verify_endpoint: str = Field(
        default_factory=lambda: f"{os.getenv('BASE_USSO_URL') or 'https://sso.usso.io'}/api/sso/v1/apikeys/verify"
    )


class AuthConfig(usso_jwt.config.JWTConfig):
    """Configuration for JWT processing."""

    api_key_header: APIHeaderConfig | None = APIHeaderConfig(
        type="CustomHeader", name="x-api-key"
    )
    jwt_header: HeaderConfig | None = HeaderConfig()
    static_api_keys: list[str] | None = None

    def __init__(self, **data: object) -> None:
        if not data:
            if os.getenv("JWT_CONFIG"):
                data = json.loads(os.getenv("JWT_CONFIG"))
            else:
                base_url = os.getenv("USSO_BASE_URL", "https://sso.usso.io")
                data = {"jwks_url": f"{base_url}/.well-known/jwks.json"}

        super().__init__(**data)

    def get_api_key(self, request: object) -> str | None:
        if self.api_key_header:
            return self.api_key_header.get_key(request)
        return None

    def get_jwt(self, request: object) -> str | None:
        if self.jwt_header:
            return self.jwt_header.get_key(request)
        return None

    def verify_token(
        self, token: str, *, raise_exception: bool = True, **kwargs: dict
    ) -> bool:
        from usso_jwt import exceptions as jwt_exceptions
        from usso_jwt import schemas

        try:
            return schemas.JWT(
                token=token,
                config=self,
                payload_class=UserData,
            ).verify(**kwargs)
        except jwt_exceptions.JWTError:
            if raise_exception:
                raise
            return False

    @classmethod
    def _parse_config(
        cls, config: Union[str, dict, "AuthConfig"]
    ) -> "AuthConfig":
        """Parse a single JWT configuration."""
        if isinstance(config, str):
            config = json.loads(config)
        if isinstance(config, dict):
            return cls(**config)
        if isinstance(config, cls):
            return config
        raise ValueError("Invalid JWT configuration")

    @classmethod
    def validate_jwt_configs(
        cls,
        jwt_config: Union[
            str, dict, "AuthConfig", list[str], list[dict], list["AuthConfig"]
        ],
    ) -> list["AuthConfig"]:
        if isinstance(jwt_config, (str, dict, cls)):
            return [cls._parse_config(jwt_config)]
        if isinstance(jwt_config, list):
            return [cls._parse_config(config) for config in jwt_config]
        raise ValueError("Invalid jwt_config format")


AvailableJwtConfigs = (
    str | dict | AuthConfig | list[str] | list[dict] | list[AuthConfig]
)

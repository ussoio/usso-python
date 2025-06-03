import json
from typing import Any, Literal, Union

import usso_jwt.config
from pydantic import BaseModel, model_validator

from ..models.user import UserData
from ..utils.string_utils import get_authorization_scheme_param


class HeaderConfig(BaseModel):
    type: Literal["Authorization", "Cookie", "CustomHeader"] = "Cookie"
    name: str = "usso_access_token"

    @model_validator(mode="before")
    def validate_header(cls, data: dict):
        if data.get("type") == "Authorization" and not data.get("name"):
            data["name"] = "Bearer"
        elif data.get("type") == "Cookie":
            data["name"] = data.get("name", "usso_access_token")
        elif data.get("type") == "CustomHeader":
            data["name"] = data.get("name", "x-usso-access-token")
        return data

    def __hash__(self):
        return hash(self.model_dump_json())

    def get_key(self, request) -> str | None:
        headers: dict[str, Any] = getattr(request, "headers", {})
        cookies: dict[str, str] = getattr(
            request, "cookies", headers.get("Cookie", {})
        )
        if self.type == "CustomHeader":
            return headers.get(self.name)
        elif self.type == "Cookie":
            return cookies.get(self.name)
        elif self.type == "Authorization":
            authorization = headers.get("Authorization")
        if self.type == "Authorization":
            authorization = headers.get("Authorization")
            scheme, credentials = get_authorization_scheme_param(authorization)
            if scheme.lower() == self.name.lower():
                return credentials


class APIHeaderConfig(HeaderConfig):
    verify_endpoint: str = "https://sso.usso.io/api_key/verify"


class AuthConfig(usso_jwt.config.JWTConfig):
    """Configuration for JWT processing."""

    api_key_header: APIHeaderConfig | None = APIHeaderConfig(
        type="CustomHeader", name="x-api-key"
    )
    jwt_header: HeaderConfig | None = HeaderConfig()
    static_api_keys: list[str] | None = None

    def get_api_key(self, request) -> str | None:
        if self.api_key_header:
            return self.api_key_header.get_key(request)
        return None

    def get_jwt(self, request) -> str | None:
        if self.jwt_header:
            return self.jwt_header.get_key(request)
        return None

    def verify_token(
        self, token: str, *, raise_exception: bool = True, **kwargs
    ) -> bool:
        from usso_jwt import exceptions as jwt_exceptions
        from usso_jwt import schemas

        try:
            return schemas.JWT(
                token=token,
                config=self,
                payload_class=UserData,
            ).verify(**kwargs)
        except jwt_exceptions.JWTError as e:
            if raise_exception:
                raise e
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

"""Authentication configuration classes."""

import json
import os
from typing import Any, Union

import usso_jwt.config
from pydantic import BaseModel, Field

from .user import UserData
from .utils.string_utils import get_authorization_scheme_param


class HeaderConfig(BaseModel):
    """
    Configuration for extracting authentication tokens from HTTP requests.

    Supports both header-based and cookie-based token extraction.

    Attributes:
        header_name: Name of the HTTP header containing the token.
            Defaults to "Authorization".
        cookie_name: Name of the cookie containing the token.
            Defaults to "usso-access-token".

    """

    header_name: str | None = "Authorization"
    cookie_name: str | None = "usso-access-token"

    def __hash__(self) -> int:
        """
        Generate a hash for the configuration.

        Returns:
            int: Hash value based on the JSON representation.

        """
        return hash(self.model_dump_json())

    def _get_key_header(self, request: object) -> str | None:
        """
        Extract token from HTTP header.

        Args:
            request: The HTTP request object.

        Returns:
            str | None: The token value if found, None otherwise.

        """
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
        """
        Extract token from HTTP cookie.

        Args:
            request: The HTTP request object.

        Returns:
            str | None: The token value if found, None otherwise.

        """
        if not self.cookie_name:
            return None

        getattr(request, "headers", {})
        cookies: dict[str, str] = getattr(request, "cookies", {})
        return cookies.get(self.cookie_name)

    def get_key(self, request: object) -> str | None:  # type: ignore
        """
        Extract token from request (header or cookie).

        Tries header first, then falls back to cookie.

        Args:
            request: The HTTP request object.

        Returns:
            str | None: The token value if found, None otherwise.

        """
        return self._get_key_header(request) or self._get_key_cookie(request)


class APIHeaderConfig(HeaderConfig):
    """
    Configuration for API key authentication.

    Extends HeaderConfig with API key-specific settings including
    the verification endpoint.

    Attributes:
        header_name: Name of the HTTP header containing the API key.
            Defaults to "x-api-key".
        cookie_name: Not used for API keys (set to None).
        verify_endpoint: URL endpoint for verifying API keys.
            Defaults to USSO_BASE_URL/api/sso/v1/apikeys/verify.

    """

    header_name: str | None = "x-api-key"
    cookie_name: str | None = None
    verify_endpoint: str = Field(
        default_factory=lambda: f"{os.getenv('USSO_BASE_URL') or 'https://sso.usso.io'}/api/sso/v1/apikeys/verify"
    )


class AuthConfig(usso_jwt.config.JWTConfig):
    """Configuration for JWT processing."""

    api_key_header: APIHeaderConfig | None = APIHeaderConfig(
        type="CustomHeader", name="x-api-key"
    )
    jwt_header: HeaderConfig | None = HeaderConfig()
    static_api_keys: list[str] | None = None

    def __init__(self, **data: object) -> None:
        """
        Initialize authentication configuration.

        If no data is provided, attempts to load from JWT_CONFIG environment
        variable, or creates a default configuration using USSO_BASE_URL.

        Args:
            **data: Configuration data (jwks_url, api_key_header, etc.).

        """
        if not data:
            if os.getenv("JWT_CONFIG"):
                data = json.loads(os.getenv("JWT_CONFIG"))
            else:
                base_url = os.getenv("USSO_BASE_URL", "https://sso.usso.io")
                data = {"jwks_url": f"{base_url}/.well-known/jwks.json"}

        super().__init__(**data)

    def get_api_key(self, request: object) -> str | None:
        """
        Extract API key from request.

        Args:
            request: The HTTP request object.

        Returns:
            str | None: The API key if found, None otherwise.

        """
        if self.api_key_header:
            return self.api_key_header.get_key(request)
        return None

    def get_jwt(self, request: object) -> str | None:
        """
        Extract JWT token from request.

        Args:
            request: The HTTP request object.

        Returns:
            str | None: The JWT token if found, None otherwise.

        """
        if self.jwt_header:
            return self.jwt_header.get_key(request)
        return None

    def verify_token(
        self, token: str, *, raise_exception: bool = True, **kwargs: dict
    ) -> bool:
        """
        Verify a JWT token.

        Args:
            token: The JWT token string to verify.
            raise_exception: Whether to raise an exception on
                verification failure.
            **kwargs: Additional arguments for token verification.

        Returns:
            bool: True if token is valid, False otherwise.

        Raises:
            JWTError: If token is invalid and raise_exception is True.

        """
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
        """
        Parse a single JWT configuration from various formats.

        Args:
            config: Configuration as string (JSON), dict, or
                AuthConfig instance.

        Returns:
            AuthConfig: Parsed configuration object.

        Raises:
            ValueError: If the configuration format is invalid.

        """
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
        """
        Validate and normalize JWT configurations.

        Accepts a single configuration or a list of configurations in various
        formats and returns a list of AuthConfig instances.

        Args:
            jwt_config: Configuration(s) as string, dict, AuthConfig,
                or lists thereof.

        Returns:
            list[AuthConfig]: List of validated AuthConfig instances.

        Raises:
            ValueError: If the configuration format is invalid.

        """
        if isinstance(jwt_config, (str, dict, cls)):
            return [cls._parse_config(jwt_config)]
        if isinstance(jwt_config, list):
            return [cls._parse_config(config) for config in jwt_config]
        raise ValueError("Invalid jwt_config format")


AvailableJwtConfigs = (
    str | dict | AuthConfig | list[str] | list[dict] | list[AuthConfig]
)

import json
import logging
import os
from urllib.parse import urlparse

import usso_jwt.exceptions
import usso_jwt.schemas

from .api_key import fetch_api_key_data, fetch_api_key_data_async
from .config import AuthConfig, AvailableJwtConfigs
from .exceptions import _handle_exception
from .user import UserData

logger = logging.getLogger("usso")


class UssoAuth:
    """Main authentication client for USSO.

    This client handles token validation, user data retrieval,
    and API key verification.
    """

    def __init__(
        self,
        *,
        jwt_config: AvailableJwtConfigs | None = None,
        from_usso_base_url: str | None = None,
        **kwargs: object,
    ) -> None:
        """Initialize the USSO authentication client.

        Args:
            jwt_config: JWT configuration(s) to use for token validation

        """
        if jwt_config is None:
            if os.getenv("JWT_CONFIGS"):
                jwt_config = json.loads(os.getenv("JWT_CONFIGS"))
            else:
                jwt_config = AuthConfig()
                from_usso_base_url = os.getenv("USSO_BASE_URL")
        self.jwt_configs = AuthConfig.validate_jwt_configs(jwt_config)
        self.from_usso_base_url = from_usso_base_url

    def user_data_from_token(
        self,
        token: str,
        *,
        expected_token_type: str | None = "access",  # noqa: S107
        raise_exception: bool = True,
        **kwargs: dict,
    ) -> UserData | None:
        """Get user data from a JWT token.

        Args:
            token: The JWT token to validate
            expected_token_type: Expected token type
            raise_exception: Whether to raise exception on error
            **kwargs: Additional arguments to pass to token verification

        Returns:
            UserData if token is valid, None otherwise

        Raises:
            USSOException: If token is invalid and raise_exception is True

        """
        exp = None

        if self.from_usso_base_url:
            try:
                jwt_obj = usso_jwt.schemas.JWT(
                    token=token,
                    config=self.jwt_configs[0],
                    payload_class=UserData,
                )
                iss = jwt_obj.unverified_payload.iss
                iss_domain = urlparse(iss).netloc
                jwks_url = (
                    f"{self.from_usso_base_url}/.well-known/jwks.json?"
                    f"domain={iss_domain}"
                )
                jwt_obj.config.jwks_url = jwks_url
                if jwt_obj.verify(
                    expected_token_type=expected_token_type,
                    **kwargs,
                ):
                    return jwt_obj.payload
            except usso_jwt.exceptions.JWTError as e:
                exp = e

        for jwk_config in self.jwt_configs:
            try:
                jwt_obj = usso_jwt.schemas.JWT(
                    token=token, config=jwk_config, payload_class=UserData
                )
                if jwt_obj.verify(
                    expected_token_type=expected_token_type,
                    **kwargs,
                ):
                    return jwt_obj.payload
            except usso_jwt.exceptions.JWTError as e:
                exp = e

        _handle_exception(
            "Unauthorized",
            message=str(exp) if exp else None,
            raise_exception=raise_exception,
            **kwargs,
        )

    def user_data_from_api_key(self, api_key: str) -> UserData:
        """Get user data from an API key.

        Args:
            api_key: The API key to verify

        Returns:
            UserData: The user data associated with the API key

        Raises:
            USSOException: If the API key is invalid

        """
        return fetch_api_key_data(
            self.jwt_configs[0].api_key_header.verify_endpoint,
            api_key,
        )

    async def user_data_from_api_key_async(self, api_key: str) -> UserData:
        """Get user data from an API key.

        Args:
            api_key: The API key to verify

        Returns:
            UserData: The user data associated with the API key

        Raises:
            USSOException: If the API key is invalid

        """
        return await fetch_api_key_data_async(
            self.jwt_configs[0].api_key_header.verify_endpoint,
            api_key,
        )

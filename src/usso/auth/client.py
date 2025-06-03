import logging

import usso_jwt.exceptions
import usso_jwt.schemas

from ..exceptions import _handle_exception
from ..models.user import UserData
from .api_key import fetch_api_key_data
from .config import AuthConfig, AvailableJwtConfigs

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
    ):
        """Initialize the USSO authentication client.

        Args:
            jwt_config: JWT configuration(s) to use for token validation
        """
        if jwt_config is None:
            jwt_config = AuthConfig()
        self.jwt_configs = AuthConfig.validate_jwt_configs(jwt_config)

    def user_data_from_token(
        self,
        token: str,
        *,
        expected_acr: str | None = "access",
        raise_exception: bool = True,
        **kwargs,
    ) -> UserData | None:
        """Get user data from a JWT token.

        Args:
            token: The JWT token to validate
            expected_acr: Expected authentication context reference
            raise_exception: Whether to raise exception on error
            **kwargs: Additional arguments to pass to token verification

        Returns:
            UserData if token is valid, None otherwise

        Raises:
            USSOException: If token is invalid and raise_exception is True
        """
        exp = None
        for jwk_config in self.jwt_configs:
            try:
                jwt_obj = usso_jwt.schemas.JWT(
                    token=token, config=jwk_config, payload_class=UserData
                )
                if jwt_obj.verify(expected_acr=expected_acr, **kwargs):
                    return jwt_obj.payload
            except usso_jwt.exceptions.JWTError as e:
                exp = e

        if raise_exception:
            if exp:
                _handle_exception("unauthorized", message=str(exp), **kwargs)
            _handle_exception("unauthorized", **kwargs)

    def user_data_from_api_key(self, api_key: str) -> UserData:
        """Get user data from an API key.

        Args:
            api_key: The API key to verify

        Returns:
            UserData: The user data associated with the API key

        Raises:
            USSOException: If the API key is invalid
        """
        return fetch_api_key_data(self.jwt_configs[0].jwk_url, api_key)

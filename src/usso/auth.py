"""USSO authentication client."""

import base64
import binascii
import json
import logging
import os
import re
from urllib.parse import urlparse

import usso_jwt.exceptions
import usso_jwt.schemas

from .api_key import fetch_api_key_data, fetch_api_key_data_async
from .config import AuthConfig, AvailableJwtConfigs
from .exceptions import _handle_exception
from .user import UserData

logger = logging.getLogger("usso")


class UssoAuth:
    """
    Main authentication client for USSO.

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
        """
        Initialize the USSO authentication client.

        Args:
            jwt_config: JWT configuration(s) to use for token validation.
            from_usso_base_url: Base URL for dynamic JWKS resolution.
            **kwargs: Additional arguments (currently unused).

        """
        if jwt_config is None:
            if os.getenv("JWT_CONFIGS"):
                jwt_config = json.loads(os.getenv("JWT_CONFIGS"))
            elif os.getenv("JWT_CONFIG"):
                jwt_config = json.loads(os.getenv("JWT_CONFIG"))
            else:
                from_usso_base_url = os.getenv("USSO_BASE_URL")
                jwt_config = AuthConfig()
        self.jwt_configs = AuthConfig.validate_jwt_configs(jwt_config)
        self.from_usso_base_url = from_usso_base_url

    @staticmethod
    def is_base64url_segment(segment: str) -> bool:
        """
        Return True when a JWT/JWE compact segment is base64url.

        Notes:
            JWT/JWS/JWE compact serialization uses base64url segments (often
            without padding). We validate by normalizing padding and trying to
            decode via urlsafe_b64decode.
        """
        if not segment:
            return False

        # Reject whitespace early (fast path).
        if any(ch.isspace() for ch in segment):
            return False

        # JWT base64url uses A-Za-z0-9_- with optional '=' padding at the end.
        if not re.fullmatch(r"[A-Za-z0-9_-]+=?=?", segment):
            return False

        # Normalize: remove existing padding, then add the correct amount.
        base = segment.rstrip("=")
        if not base:
            return False

        if not re.fullmatch(r"[A-Za-z0-9_-]+", base):
            return False

        padding_needed = (-len(base)) % 4
        padded = base + ("=" * padding_needed)

        try:
            base64.urlsafe_b64decode(padded.encode("ascii"))
        except (binascii.Error, ValueError):
            return False
        else:
            return True

    @classmethod
    def detect_compact_token_type(cls, token: str) -> str | None:
        """
        Detect compact token type.

        Returns:
            - "jwt" for JWS compact serialization (3 segments)
            - "jwe" for JWE compact serialization (5 segments)
            - None otherwise
        """
        token = token.strip()
        parts = token.split(".")

        if len(parts) == 3 and all(cls.is_base64url_segment(p) for p in parts):
            return "jwt"
        if len(parts) == 5 and all(cls.is_base64url_segment(p) for p in parts):
            return "jwe"
        return None

    def user_data_from_token(
        self,
        token: str,
        *,
        expected_token_type: str | None = "access",  # noqa: S107
        raise_exception: bool = True,
        **kwargs: dict,
    ) -> UserData | None:
        """
        Get user data from a JWT token.

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
        """
        Get user data from an API key.

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
        """
        Get user data from an API key.

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

    def user_data_from_jwe(
        self,
        jwe: str,
        *,
        raise_exception: bool = True,
    ) -> UserData | None:
        """
        JWE verification support (not yet implemented).

        For now, we intentionally do NOT fall back to API key verification
        when the bearer token looks like a compact JWE.

        Args:
            jwe: The JWE token to verify
            raise_exception: Whether to raise exception on error

        Returns:
            UserData | None: User data if token is valid, None otherwise

        """
        _handle_exception(
            "Unauthorized",
            message="JWE is not supported yet",
            raise_exception=raise_exception,
        )
        return None

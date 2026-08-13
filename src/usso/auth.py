"""USSO authentication client."""

import asyncio
import base64
import binascii
import inspect
import json
import logging
import os
import re
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlparse

import usso_jwt.exceptions
import usso_jwt.schemas

from .api_key import fetch_api_key_data, fetch_api_key_data_async
from .config import APIHeaderConfig, AuthConfig, AvailableJwtConfigs
from .exceptions import _handle_exception, _raise_auth_error
from .user import TokenType, UserData

if TYPE_CHECKING:
    from collections.abc import Awaitable

logger = logging.getLogger("usso")

# Compact serialization segment counts (RFC 7515 / RFC 7516).
_JWS_COMPACT_SEGMENTS = 3
_JWE_COMPACT_SEGMENTS = 5


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
        del kwargs  # reserved for future options
        if jwt_config is None:
            jwt_configs_env = os.getenv("JWT_CONFIGS")
            jwt_config_env = os.getenv("JWT_CONFIG")
            if jwt_configs_env:
                jwt_config = json.loads(jwt_configs_env)
            elif jwt_config_env:
                jwt_config = json.loads(jwt_config_env)
            else:
                from_usso_base_url = os.getenv("USSO_BASE_URL")
                jwt_config = AuthConfig()
        self.jwt_configs = AuthConfig.validate_jwt_configs(jwt_config)
        self.from_usso_base_url = from_usso_base_url

    @staticmethod
    def is_base64url_segment(  # ruff: ignore[too-many-return-statements]
        segment: str,
    ) -> bool:
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

        if len(parts) == _JWS_COMPACT_SEGMENTS and all(
            cls.is_base64url_segment(p) for p in parts
        ):
            return "jwt"
        if len(parts) == _JWE_COMPACT_SEGMENTS and all(
            cls.is_base64url_segment(p) for p in parts
        ):
            return "jwe"
        return None

    def _user_data_from_usso_base_url(
        self,
        token: str,
        *,
        expected: str,
        verify_kwargs: dict[str, Any],
    ) -> UserData | None:
        """Verify token using JWKS derived from from_usso_base_url + iss."""
        jwt_obj = usso_jwt.schemas.JWT(
            token=token,
            config=self.jwt_configs[0],
            payload_class=UserData,
        )
        unverified = jwt_obj.unverified_payload
        iss = getattr(unverified, "iss", None)
        if isinstance(unverified, dict):
            iss = unverified.get("iss")
        iss_domain = urlparse(str(iss or "")).netloc
        jwt_obj.config.jwks_url = (
            f"{self.from_usso_base_url}/.well-known/jwks.json?"
            f"domain={iss_domain}"
        )
        if jwt_obj.verify(
            expected_token_type=expected,
            **verify_kwargs,
        ):
            return cast("UserData", jwt_obj.payload)
        return None

    def user_data_from_token(
        self,
        token: str,
        *,
        expected_token_type: str | TokenType | None = None,
        raise_exception: bool = True,
        **kwargs: object,
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
        if expected_token_type is None:
            expected_token_type = TokenType.ACCESS
        expected = (
            expected_token_type.value
            if isinstance(expected_token_type, TokenType)
            else expected_token_type
        )
        exp: BaseException | None = None
        verify_kwargs = cast("dict[str, Any]", kwargs)

        if self.from_usso_base_url:
            try:
                user = self._user_data_from_usso_base_url(
                    token,
                    expected=expected,
                    verify_kwargs=verify_kwargs,
                )
            except usso_jwt.exceptions.JWTError as e:
                exp = e
            else:
                if user is not None:
                    return user

        for jwk_config in self.jwt_configs:
            try:
                jwt_obj = usso_jwt.schemas.JWT(
                    token=token, config=jwk_config, payload_class=UserData
                )
                if jwt_obj.verify(
                    expected_token_type=expected,
                    **verify_kwargs,
                ):
                    return cast("UserData", jwt_obj.payload)
            except usso_jwt.exceptions.JWTError as e:
                exp = e

        _handle_exception(
            "Unauthorized",
            message=str(exp) if exp else None,
            raise_exception=raise_exception,
        )
        return None

    def _resolve_api_key_header(self) -> APIHeaderConfig | None:
        """Return the first configured API key header settings."""
        for jwt_config in self.jwt_configs:
            if jwt_config.api_key_header is not None:
                return jwt_config.api_key_header
        return None

    @staticmethod
    def _run_sync_api_key_verifier(
        header: APIHeaderConfig, api_key: str
    ) -> UserData:
        """Verify an API key using a configured in-process verifier."""
        if header.api_key_verifier is not None:
            return header.api_key_verifier(api_key)

        if header.api_key_verifier_async is not None:
            result = header.api_key_verifier_async(api_key)
            if not inspect.isawaitable(result):
                return cast("UserData", result)
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                if inspect.iscoroutine(result):
                    return cast("UserData", asyncio.run(result))

                async def _await_result() -> UserData:
                    return await cast("Awaitable[UserData]", result)

                return asyncio.run(_await_result())
            if inspect.iscoroutine(result):
                result.close()
            raise RuntimeError(
                "Async api_key_verifier_async cannot be used from a running "
                "event loop; call user_data_from_api_key_async instead."
            )

        raise RuntimeError("No in-process API key verifier configured")

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
        header = self._resolve_api_key_header()
        if header is None:
            _raise_auth_error(
                "Unauthorized",
                message="API key authentication is not configured",
            )
        if header.api_key_verifier is not None or (
            header.api_key_verifier_async is not None
        ):
            return self._run_sync_api_key_verifier(header, api_key)
        return fetch_api_key_data(header.verify_endpoint, api_key)

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
        header = self._resolve_api_key_header()
        if header is None:
            _raise_auth_error(
                "Unauthorized",
                message="API key authentication is not configured",
            )
        if header.api_key_verifier_async is not None:
            return await header.api_key_verifier_async(api_key)
        if header.api_key_verifier is not None:
            return header.api_key_verifier(api_key)
        return await fetch_api_key_data_async(header.verify_endpoint, api_key)

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
        del jwe  # reserved until JWE support lands
        _handle_exception(
            "Unauthorized",
            message="JWE is not supported yet",
            raise_exception=raise_exception,
        )
        return None

    async def user_data_from_jwe_async(
        self,
        jwe: str,
        *,
        raise_exception: bool = True,
    ) -> UserData | None:
        """Async wrapper for JWE verification (not yet implemented)."""
        return self.user_data_from_jwe(jwe, raise_exception=raise_exception)

"""Base client class for USSO authentication."""

import os
from typing import Self

from usso_jwt.schemas import JWT, JWTConfig


class BaseUssoClient:
    """
    Base client class for USSO authentication.

    Provides common functionality for both sync and async USSO clients,
    including authentication setup, token management, and configuration.

    Args:
        api_key: API key for authentication. Defaults to USSO_API_KEY env var.
        agent_id: Agent ID for agent-based authentication.
            Defaults to AGENT_ID env var.
        agent_private_key: Private key for agent-based authentication.
            Defaults to AGENT_PRIVATE_KEY env var.
        refresh_token: Refresh token for token-based authentication.
            Defaults to USSO_REFRESH_TOKEN env var.
        usso_base_url: Base URL for USSO API.
            Defaults to USSO_BASE_URL env var or "https://sso.usso.io".
        client: Optional existing client to copy attributes from.

    Raises:
        ValueError: If none of the required authentication credentials
            are provided.

    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        agent_id: str | None = None,
        agent_private_key: str | None = None,
        refresh_token: str | None = None,
        usso_base_url: str | None = os.getenv(
            "USSO_BASE_URL", "https://sso.usso.io"
        ),
        client: Self | None = None,
    ) -> None:
        """
        Initialize the base USSO client.

        See class docstring for parameter details.
        """
        if client:
            self.copy_attributes_from(client)
            return

        self.usso_base_url = usso_base_url.rstrip("/")
        self.usso_refresh_url = f"{self.usso_base_url}/api/sso/v1/auth/refresh"

        api_key = api_key or os.getenv("USSO_API_KEY")
        refresh_token = refresh_token or os.getenv("USSO_REFRESH_TOKEN")
        agent_id = agent_id or os.getenv("AGENT_ID")
        agent_private_key = agent_private_key or os.getenv("AGENT_PRIVATE_KEY")

        if (
            not api_key
            and not refresh_token
            and not (agent_id and agent_private_key)
        ):
            raise ValueError(
                "one of api_key, refresh_token, "
                "agent_id and agent_private_key is required"
            )

        self.api_key = api_key
        self.agent_id = agent_id
        self.agent_private_key = agent_private_key
        self._refresh_token = (
            JWT(
                token=refresh_token,
                config=JWTConfig(
                    jwks_url=f"{self.usso_base_url}/.well-known/jwks.json"
                ),
            )
            if refresh_token
            else None
        )
        self.access_token = None

        if self.api_key:
            self.headers = self.headers or {}
            self.headers.update({"x-api-key": self.api_key})

    def copy_attributes_from(self, client: Self) -> None:
        """
        Copy authentication attributes from another client instance.

        Args:
            client: The client instance to copy attributes from.

        """
        self.usso_base_url = client.usso_base_url
        self._refresh_token = client._refresh_token
        self.access_token = client.access_token
        self.api_key = client.api_key
        self.agent_id = client.agent_id
        self.agent_private_key = client.agent_private_key
        self.headers = client.headers.copy()

    @property
    def refresh_token(self) -> JWT:
        """
        Get the refresh token, validating it if present.

        If the refresh token is invalid or expired, it is cleared.

        Returns:
            JWT: The refresh token JWT object, or None if invalid/expired.

        """
        if (
            self._refresh_token
            and self._refresh_token.verify(
                expected_token_type="refresh",  # noqa: S106
            )
            and self._refresh_token.is_temporally_valid()
        ):
            self._refresh_token = None

        return self._refresh_token

"""Synchronous HTTP client for USSO API."""

import os
from typing import Self

import httpx
from usso_jwt.schemas import JWT, JWTConfig

from ..schemas import UserResponse
from ..utils import agent
from .base_client import BaseUssoClient


class UssoClient(httpx.Client, BaseUssoClient):
    """
    Synchronous HTTP client for USSO API.

    This client extends httpx.Client and provides authentication
    capabilities including API key, refresh token, and agent token support.
    It automatically handles token refresh and session management.

    Args:
        api_key: API key for authentication. Defaults to USSO_API_KEY env var.
        agent_id: Agent ID for agent-based authentication.
            Defaults to AGENT_ID env var.
        private_key: Private key for agent-based authentication.
            Defaults to AGENT_PRIVATE_KEY env var.
        refresh_token: Refresh token for token-based authentication.
            Defaults to USSO_REFRESH_TOKEN env var.
        usso_base_url: Base URL for USSO API.
            Defaults to USSO_BASE_URL env var or "https://sso.usso.io".
        client: Optional existing client to copy attributes from.
        **kwargs: Additional arguments passed to httpx.Client.

    """

    def __init__(
        self,
        *,
        api_key: str | None = os.getenv("USSO_API_KEY"),
        agent_id: str | None = os.getenv("AGENT_ID"),
        private_key: str | None = os.getenv("AGENT_PRIVATE_KEY"),
        refresh_token: str | None = os.getenv("USSO_REFRESH_TOKEN"),
        usso_base_url: str | None = os.getenv(
            "USSO_BASE_URL", "https://sso.usso.io"
        ),
        client: Self | None = None,
        **kwargs: dict,
    ) -> None:
        """
        Initialize the synchronous USSO client.

        See class docstring for parameter details.
        """
        httpx.Client.__init__(self, base_url=usso_base_url, **kwargs)

        BaseUssoClient.__init__(
            self,
            api_key=api_key,
            agent_id=agent_id,
            private_key=private_key,
            refresh_token=refresh_token,
            usso_base_url=usso_base_url,
            client=client,
        )
        if not self.api_key:
            self._refresh()

    def _refresh(self) -> dict:
        """
        Refresh the access token using the refresh token.

        Returns:
            dict: Response data containing new tokens.

        Raises:
            ValueError: If refresh_token is not available.
            httpx.HTTPStatusError: If the refresh request fails.

        """
        if not self.refresh_token:
            raise ValueError("refresh_token is required")

        response = httpx.post(
            self.usso_refresh_url,
            json={"refresh_token": f"{self.refresh_token}"},
        )
        response.raise_for_status()
        self.access_token = JWT(
            token=response.json().get("access_token"),
            config=JWTConfig(
                jwks_url=f"{self.usso_base_url}/.well-known/jwks.json"
            ),
        )
        self.headers.update({"Authorization": f"Bearer {self.access_token}"})
        return response.json()

    def get_session(self) -> Self:
        """
        Get or refresh the current session.

        If using API key authentication, returns self immediately.
        Otherwise, refreshes the access token if it's missing or expired.

        Returns:
            Self: The client instance with a valid session.

        """
        if self.api_key:
            return self

        if not self.access_token or self.access_token.is_temporally_valid():
            self._refresh()
        return self

    def _request(
        self, method: str, url: str, **kwargs: dict
    ) -> httpx.Response:
        """
        Make an authenticated HTTP request.

        Ensures the session is valid before making the request.

        Args:
            method: HTTP method (GET, POST, etc.).
            url: Request URL.
            **kwargs: Additional arguments passed to httpx request.

        Returns:
            httpx.Response: The HTTP response.

        """
        self.get_session()
        return super().request(self, method, url, **kwargs)

    def use_agent_token(
        self,
        scopes: list[str],
        aud: str,
        tenant_id: str,
    ) -> str:
        """
        Generate and use an agent token for authentication.

        Creates a JWT for the agent, exchanges it for an access token,
        and updates the client headers.

        Args:
            scopes: List of scopes to request for the agent token.
            aud: Audience for the JWT.
            tenant_id: Tenant ID for the agent token.

        Returns:
            str: The access token obtained from the agent authentication.

        Raises:
            ValueError: If agent_id or private_key are not set.

        """
        if not self.agent_id or not self.private_key:
            raise ValueError("agent_id and private_key are required")

        jwt = agent.generate_agent_jwt(
            scopes=scopes,
            aud=aud,
            tenant_id=tenant_id,
            agent_id=self.agent_id,
            private_key=self.private_key,
        )
        token = agent.get_agent_token(jwt)
        self.headers.update({"Authorization": f"Bearer {token}"})
        return token

    def get_users(self, params: dict | None = None) -> list[UserResponse]:
        """
        Get users from USSO API.

        Returns:
            list[UserResponse]: List of users.

        """
        response = self.get("/api/sso/v1/users", params=params)
        if response.status_code != 200:
            import logging

            logging.error("Error getting users: %s", response.json())
        response.raise_for_status()
        return [
            UserResponse.model_validate(user)
            for user in response.json().get("items", [])
        ]

    def create_users(self, data: dict | None = None) -> UserResponse:
        """
        Create a user in USSO API.

        Returns:
            UserResponse: Created user.

        """
        response = self.post("/api/sso/v1/users", json=data)
        response.raise_for_status()
        return UserResponse.model_validate(response.json())

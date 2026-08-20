"""Asynchronous HTTP client for USSO API."""

import os
from typing import Any, Self

import httpx
from aiocache import cached
from usso_jwt.schemas import JWT, JWTConfig

from ..exceptions import PermissionDenied
from ..schemas import UserResponse
from ..utils import agent
from .base_client import BaseUssoClient, jwt_from_token, payload_scopes


class AsyncUssoClient(httpx.AsyncClient, BaseUssoClient):
    """
    Asynchronous HTTP client for USSO API.

    This client extends httpx.AsyncClient and provides authentication
    capabilities including API key, refresh token, and agent token support.
    It automatically handles token refresh and session management.

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
        **kwargs: Additional arguments passed to httpx.AsyncClient.

    """

    def __init__(
        self,
        *,
        api_key: str | None = os.getenv("USSO_API_KEY"),
        agent_id: str | None = os.getenv("AGENT_ID"),
        agent_private_key: str | None = os.getenv("AGENT_PRIVATE_KEY"),
        refresh_token: str | None = os.getenv("USSO_REFRESH_TOKEN"),
        usso_base_url: str | None = os.getenv(
            "USSO_BASE_URL", "https://sso.usso.io"
        ),
        client: Self | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the async USSO client.

        See class docstring for parameter details.
        """
        base_url = (
            usso_base_url
            or os.getenv("USSO_BASE_URL")
            or "https://sso.usso.io"
        )
        httpx.AsyncClient.__init__(self, base_url=base_url, **kwargs)
        BaseUssoClient.__init__(
            self,
            usso_base_url=usso_base_url,
            api_key=api_key,
            agent_id=agent_id,
            agent_private_key=agent_private_key,
            refresh_token=refresh_token,
            client=client,
        )
        if self._refresh_token:
            self._refresh_sync()

    def _handle_refresh_response(self, response: httpx.Response) -> dict:
        """
        Process the response from refresh token requests.

        Extracts access and refresh tokens from the response,
        creates JWT objects, and updates the client headers
        with the new access token.

        Args:
            response: HTTP response from the refresh endpoint.

        Returns:
            dict: Response data containing tokens.

        Raises:
            httpx.HTTPStatusError: If the response status indicates an error.

        """
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        self.access_token = jwt_from_token(
            self.usso_base_url,
            data.get("access_token") or "",
        )
        refresh_data = data.get("token")
        refresh_token = (
            refresh_data.get("refresh_token")
            if isinstance(refresh_data, dict)
            else None
        )
        self._refresh_token = jwt_from_token(
            self.usso_base_url,
            refresh_token or "",
        )
        if self.access_token:
            self.headers.update({
                "Authorization": f"Bearer {self.access_token}"
            })
        return data

    def _refresh_sync(self) -> dict:
        """
        Refresh access token synchronously using refresh token.

        Returns:
            dict: Response data containing new tokens.

        Raises:
            ValueError: If refresh_token is not available.
            httpx.HTTPStatusError: If the refresh request fails.

        """
        # Prefer internal `_refresh_token` (tests may set it directly),
        # but fall back to the `refresh_token` property so PropertyMock-based
        # tests keep working too.
        refresh_token_value = self._refresh_token or self.refresh_token
        if not refresh_token_value:
            raise ValueError("refresh_token or usso_api_key is required")

        response = httpx.post(
            self.usso_refresh_url,
            json={"refresh_token": f"{refresh_token_value}"},
        )
        return self._handle_refresh_response(response)

    async def _refresh(self) -> dict:
        """
        Asynchronously refresh the access token using the refresh token.

        Returns:
            dict: Response data containing new tokens.

        Raises:
            ValueError: If refresh_token is not available.
            httpx.HTTPStatusError: If the refresh request fails.

        """
        # Prefer internal `_refresh_token` (tests may set it directly),
        # but fall back to the `refresh_token` property so PropertyMock-based
        # tests keep working too.
        refresh_token_value = self._refresh_token or self.refresh_token
        if not refresh_token_value:
            raise ValueError("refresh_token or usso_api_key is required")

        response = await self.post(
            self.usso_refresh_url,
            json={"refresh_token": f"{refresh_token_value}"},
        )
        return self._handle_refresh_response(response)

    async def get_session(self) -> Self:
        """
        Get or refresh the current session.

        If using API key authentication, returns self immediately.
        Otherwise, refreshes the access token if it's missing or expired.

        Returns:
            Self: The client instance with a valid session.

        """
        if hasattr(self, "api_key") and self.api_key:
            return self

        if not (self.access_token and self.access_token.is_temporally_valid()):
            await self._refresh()
        return self

    async def _request(
        self, method: str, url: str, **kwargs: Any
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
        session = await self.get_session()
        return await session.request(method, url, **kwargs)

    def _access_token_scopes(self) -> list[str]:
        """
        Extract scopes using the module-level `payload_scopes` helper.

        Tests patch `usso.client.async_client.payload_scopes`, so this
        indirection keeps the patch effective.
        """
        return payload_scopes(self.access_token)

    async def use_agent_token(
        self,
        scopes: list[str],
        aud: str,
        tenant_id: str | None = None,
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
        if not self.agent_private_key:
            raise ValueError("private_key is required")
        if not self.agent_id:
            raise ValueError("agent_id is required")

        if not tenant_id:
            agent_response = await self._get_agent()
            tenant_id = agent_response.get("tenant_id")

        jwt = agent.generate_agent_jwt(
            scopes=scopes,
            aud=aud,
            tenant_id=tenant_id,
            agent_id=self.agent_id,
            private_key=self.agent_private_key,
        )
        token = await agent.get_agent_token_async(jwt)
        self.access_token = JWT(
            token=token,
            config=JWTConfig(
                jwks_url=f"{self.usso_base_url}/.well-known/jwks.json"
            ),
        )
        self.headers.update({"Authorization": f"Bearer {self.access_token}"})
        return token

    async def get_users(
        self, params: dict | None = None
    ) -> list[UserResponse]:
        """
        Get users from USSO API.

        Returns:
            list[UserResponse]: List of users.

        """
        response = await self.get("/api/sso/v1/users", params=params)
        response.raise_for_status()
        return [
            UserResponse.model_validate(user)
            for user in response.json().get("items", [])
        ]

    async def create_users(self, data: dict | None = None) -> UserResponse:
        """
        Create a user in USSO API.

        Returns:
            UserResponse: Created user.

        """
        response = await self.post("/api/sso/v1/users", json=data)
        response.raise_for_status()
        return UserResponse.model_validate(response.json())

    @cached(ttl=60)
    async def _get_api_key(self) -> dict:
        """Get the API key scopes."""

        response = await self.post(
            f"{self.usso_base_url}/api/sso/v1/apikeys/verify",
            json={"api_key": self.api_key},
        )
        response.raise_for_status()
        return response.json()

    @cached(ttl=600)
    async def _get_agent(self) -> dict:
        """Get the agent token scopes."""
        if not (self.agent_id and self.agent_private_key):
            return {}

        jwt = agent.generate_agent_jwt(
            scopes=[],
            aud="sso",
            agent_id=self.agent_id,
            private_key=self.agent_private_key,
        )

        response = await self.post(
            f"{self.usso_base_url}/api/sso/v1/agents/scopes",
            headers={"Authorization": f"Bearer {jwt}"},
        )
        response.raise_for_status()
        return response.json()

    async def _get_refresh_token_scopes(self) -> list[str]:
        """Get the refresh token scopes."""

        await self._refresh()
        return self._access_token_scopes()

    async def _get_scopes(self) -> list[str]:
        """Get the scopes."""

        if self.access_token and self.access_token.is_temporally_valid():
            return self._access_token_scopes()
        if self.api_key:
            api_key_response = await self._get_api_key()
            return api_key_response.get("scopes", [])
        if self.agent_id and self.agent_private_key:
            agent_response = await self._get_agent()
            return agent_response.get("scopes", [])
        if self.refresh_token:
            return await self._get_refresh_token_scopes()
        return []

    async def _get_token(
        self, scopes: str | list[str], aud: str = "sso"
    ) -> str | None:
        """
        Get authentication token for USSO service.

        Args:
            scopes: Permission scopes required
            aud: Audience for the JWT

        Returns:
            JWT token string
        """

        from .. import authorization

        if isinstance(scopes, str):
            scopes = [scopes]

        for scope in scopes:
            if not authorization.has_subset_scope(
                subset_scope=scope, user_scopes=await self._get_scopes()
            ):
                raise PermissionDenied(detail=f"Scope {scope} is not allowed")
        if not (self.agent_id and self.agent_private_key):
            return None

        return await self.use_agent_token(scopes=scopes, aud=aud)

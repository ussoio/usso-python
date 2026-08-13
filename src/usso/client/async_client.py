"""Asynchronous HTTP client for USSO API."""

import os
from typing import Any, Self, cast

import httpx
from aiocache import cached

from usso.exceptions import PermissionDenied
from usso.schemas import UserResponse
from usso.utils import agent

from .base_client import BaseUssoClient, jwt_from_token, payload_scopes


class AsyncUssoClient(httpx.AsyncClient, BaseUssoClient):
    """
    Asynchronous HTTP client for USSO API.

    This client extends httpx.AsyncClient and provides authentication
    capabilities including API key, refresh token, and agent token support.
    It automatically handles token refresh and session management.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        agent_id: str | None = None,
        agent_private_key: str | None = None,
        refresh_token: str | None = None,
        usso_base_url: str | None = None,
        client: Self | None = None,
        **kwargs: object,
    ) -> None:
        """
        Initialize the async USSO client.

        See class docstring for parameter details.
        """
        api_key = api_key if api_key is not None else os.getenv("USSO_API_KEY")
        agent_id = agent_id if agent_id is not None else os.getenv("AGENT_ID")
        agent_private_key = (
            agent_private_key
            if agent_private_key is not None
            else os.getenv("AGENT_PRIVATE_KEY")
        )
        refresh_token = (
            refresh_token
            if refresh_token is not None
            else os.getenv("USSO_REFRESH_TOKEN")
        )
        base_url = (
            usso_base_url
            or os.getenv("USSO_BASE_URL")
            or "https://sso.usso.io"
        )

        httpx.AsyncClient.__init__(
            self, base_url=base_url, **cast("Any", kwargs)
        )
        BaseUssoClient.__init__(
            self,
            usso_base_url=base_url,
            api_key=api_key,
            agent_id=agent_id,
            agent_private_key=agent_private_key,
            refresh_token=refresh_token,
            client=client,
        )
        if self._refresh_token:
            self._refresh_sync()

    def _handle_refresh_response(
        self, response: httpx.Response
    ) -> dict[str, Any]:
        """
        Process the response from refresh token requests.

        Extracts access and refresh tokens from the response,
        creates JWT objects, and updates the client headers
        with the new access token.
        """
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        access = data.get("access_token")
        if isinstance(access, str):
            self.access_token = jwt_from_token(self.usso_base_url, access)
        token_blob = data.get("token", {})
        refresh = (
            token_blob.get("refresh_token")
            if isinstance(token_blob, dict)
            else None
        )
        if isinstance(refresh, str):
            self._refresh_token = jwt_from_token(self.usso_base_url, refresh)
        if self.access_token:
            self.headers.update({
                "Authorization": f"Bearer {self.access_token}"
            })
        return data

    def _refresh_sync(self) -> dict[str, Any]:
        """Refresh access token synchronously using refresh token."""
        if not self.refresh_token:
            raise ValueError("refresh_token or usso_api_key is required")

        response = httpx.post(
            self.usso_refresh_url, json={"refresh_token": self.refresh_token}
        )
        return self._handle_refresh_response(response)

    async def _refresh(self) -> dict[str, Any]:
        """Asynchronously refresh the access token using the refresh token."""
        if not self.refresh_token:
            raise ValueError("refresh_token or usso_api_key is required")

        response = await self.post(
            self.usso_refresh_url, json={"refresh_token": self.refresh_token}
        )
        return self._handle_refresh_response(response)

    async def get_session(self) -> Self:
        """Get or refresh the current session."""
        if hasattr(self, "api_key") and self.api_key:
            return self

        if not (self.access_token and self.access_token.is_temporally_valid()):
            await self._refresh()
        return self

    async def _request(
        self, method: str, url: str, **kwargs: object
    ) -> httpx.Response:
        """Make an authenticated HTTP request."""
        session = await self.get_session()
        return await session.request(method, url, **cast("Any", kwargs))

    async def use_agent_token(
        self,
        scopes: list[str],
        aud: str,
        tenant_id: str | None = None,
    ) -> str:
        """Generate and use an agent token for authentication."""
        if not self.agent_id or not self.agent_private_key:
            raise ValueError("agent_id and private_key are required")

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
        self.access_token = jwt_from_token(self.usso_base_url, token)
        self.headers.update({"Authorization": f"Bearer {self.access_token}"})
        return token

    async def get_users(
        self, params: dict | None = None
    ) -> list[UserResponse]:
        """Get users from USSO API."""
        response = await self.get("/api/sso/v1/users", params=params)
        response.raise_for_status()
        return [
            UserResponse.model_validate(user)
            for user in response.json().get("items", [])
        ]

    async def create_users(self, data: dict | None = None) -> UserResponse:
        """Create a user in USSO API."""
        response = await self.post("/api/sso/v1/users", json=data)
        response.raise_for_status()
        return UserResponse.model_validate(response.json())

    @cached(ttl=60)
    async def _get_api_key(self) -> dict[str, Any]:
        """Get the API key scopes."""
        response = await self.post(
            f"{self.usso_base_url}/api/sso/v1/apikeys/verify",
            json={"api_key": self.api_key},
        )
        response.raise_for_status()
        return response.json()

    @cached(ttl=600)
    async def _get_agent(self) -> dict[str, Any]:
        """Get the agent token scopes."""
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
        return payload_scopes(self.access_token)

    async def _get_scopes(self) -> list[str]:
        """Get the scopes."""
        if self.access_token and self.access_token.is_temporally_valid():
            return payload_scopes(self.access_token)
        if self.api_key:
            api_key_response = await self._get_api_key()
            return list(api_key_response.get("scopes", []) or [])
        if self.agent_id and self.agent_private_key:
            agent_response = await self._get_agent()
            return list(agent_response.get("scopes", []) or [])
        if self.refresh_token:
            return await self._get_refresh_token_scopes()
        return []

    async def _get_token(
        self, scopes: str | list[str], aud: str = "sso"
    ) -> str | None:
        """Get authentication token for USSO service."""
        from usso import authorization

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

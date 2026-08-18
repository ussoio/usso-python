"""Synchronous HTTP client for USSO API."""

import os
from typing import Any, Self, cast

import cachetools.func
import httpx

from usso.enums import AuthIdentifier
from usso.exceptions import PermissionDenied
from usso.schemas import UserResponse
from usso.utils import agent

from .base_client import BaseUssoClient, jwt_from_token, payload_scopes


@cachetools.func.ttl_cache(maxsize=128, ttl=60)
def _verify_api_key(usso_base_url: str, api_key: str) -> dict[str, Any]:
    """Return cached remote API-key verification."""
    response = httpx.post(
        f"{usso_base_url}/api/sso/v1/apikeys/verify",
        json={"api_key": api_key},
    )
    response.raise_for_status()
    return response.json()


@cachetools.func.ttl_cache(maxsize=128, ttl=600)
def _fetch_agent_scopes(
    usso_base_url: str, agent_id: str | None, agent_private_key: str
) -> dict[str, Any]:
    """Return cached agent scopes."""
    jwt = agent.generate_agent_jwt(
        scopes=[],
        aud="sso",
        agent_id=agent_id,
        private_key=agent_private_key,
    )
    response = httpx.post(
        f"{usso_base_url}/api/sso/v1/agents/scopes",
        headers={"Authorization": f"Bearer {jwt}"},
    )
    response.raise_for_status()
    return response.json()


class UssoClient(httpx.Client, BaseUssoClient):
    """
    Synchronous HTTP client for USSO API.

    This client extends httpx.Client and provides authentication
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
        Initialize the synchronous USSO client.

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

        httpx.Client.__init__(
            self, base_url=base_url, **cast("Any", kwargs)
        )

        BaseUssoClient.__init__(
            self,
            api_key=api_key,
            agent_id=agent_id,
            agent_private_key=agent_private_key,
            refresh_token=refresh_token,
            usso_base_url=base_url,
            client=client,
        )
        if self._refresh_token:
            self._refresh()

    def _refresh(self) -> dict[str, Any]:
        """Refresh the access token using the refresh token."""
        if not self.refresh_token:
            raise ValueError("refresh_token is required")

        response = httpx.post(
            self.usso_refresh_url,
            json={"refresh_token": f"{self.refresh_token}"},
        )
        response.raise_for_status()
        access = response.json().get("access_token")
        if not isinstance(access, str):
            raise TypeError("access_token missing from refresh response")
        self.access_token = jwt_from_token(self.usso_base_url, access)
        self.headers.update({"Authorization": f"Bearer {self.access_token}"})
        return response.json()

    def get_session(self) -> Self:
        """Get or refresh the current session."""
        if self.api_key:
            return self

        if not (self.access_token and self.access_token.is_temporally_valid()):
            self._refresh()
        return self

    def _request(
        self, method: str, url: str, **kwargs: object
    ) -> httpx.Response:
        """Make an authenticated HTTP request."""
        self.get_session()
        return super().request(method, url, **cast("Any", kwargs))

    def use_agent_token(
        self,
        scopes: list[str],
        aud: str,
        tenant_id: str | None = None,
    ) -> str:
        """Generate and use an agent token for authentication."""
        if not self.agent_private_key:
            raise ValueError("private_key is required")

        if not tenant_id:
            agent_response = self._get_agent()
            tenant_id = agent_response.get("tenant_id")

        jwt = agent.generate_agent_jwt(
            scopes=scopes,
            aud=aud,
            tenant_id=tenant_id,
            agent_id=self.agent_id,
            private_key=self.agent_private_key,
        )
        token = agent.get_agent_token(jwt)
        self.access_token = jwt_from_token(self.usso_base_url, token)
        self.headers.update({"Authorization": f"Bearer {self.access_token}"})
        return token

    def get_users(self, params: dict | None = None) -> list[UserResponse]:
        """Get users from USSO API."""
        response = self.get("/api/sso/v1/users", params=params)
        response.raise_for_status()
        return [
            UserResponse.model_validate(user)
            for user in response.json().get("items", [])
        ]

    def create_users(self, data: dict | None = None) -> UserResponse:
        """Create a user in USSO API."""
        response = self.post("/api/sso/v1/users", json=data)
        response.raise_for_status()
        return UserResponse.model_validate(response.json())

    def get_profile(self, user_id: str) -> dict[str, Any]:
        """Get user profile from USSO API."""
        response = self.get(f"/api/sso/v1/profiles/{user_id}")
        response.raise_for_status()
        return response.json()

    def add_identifier(
        self, user_id: str, identifier_type: AuthIdentifier, identifier: str
    ) -> dict[str, Any]:
        """Add an identifier to a user."""
        response = self.post(
            f"/api/sso/v1/users/{user_id}/identifiers",
            json={"type": identifier_type, "identifier": identifier},
        )
        response.raise_for_status()
        return response.json()

    def _get_api_key(self) -> dict[str, Any]:
        """Get the API key scopes."""
        if not self.api_key:
            return {}
        return _verify_api_key(self.usso_base_url, self.api_key)

    def _get_agent(self) -> dict[str, Any]:
        """Get the agent token scopes."""
        if not self.agent_private_key:
            return {}
        return _fetch_agent_scopes(
            self.usso_base_url, self.agent_id, self.agent_private_key
        )

    def _get_refresh_token_scopes(self) -> list[str]:
        """Get the refresh token scopes."""
        self._refresh()
        return payload_scopes(self.access_token)

    def _get_scopes(self) -> list[str]:
        """Get the scopes."""
        if self.access_token and self.access_token.is_temporally_valid():
            return payload_scopes(self.access_token)
        if self.api_key:
            api_key_response = self._get_api_key()
            return list(api_key_response.get("scopes", []) or [])
        if self.agent_private_key:
            agent_response = self._get_agent()
            return list(agent_response.get("scopes", []) or [])
        if self.refresh_token:
            return self._get_refresh_token_scopes()
        return []

    def _get_token(
        self, scopes: str | list[str], aud: str = "sso"
    ) -> str | None:
        """Get authentication token for USSO service."""
        from usso import authorization

        if isinstance(scopes, str):
            scopes = [scopes]

        for scope in scopes:
            if not authorization.has_subset_scope(
                subset_scope=scope, user_scopes=self._get_scopes()
            ):
                raise PermissionDenied(detail=f"Scope {scope} is not allowed")

        if not self.agent_private_key:
            return None

        return self.use_agent_token(scopes=scopes, aud=aud)

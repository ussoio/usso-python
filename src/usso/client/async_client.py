import os
from typing import Self

import httpx
from usso_jwt.schemas import JWT, JWTConfig

from ..utils import agent
from .base_client import BaseUssoClient


class AsyncUssoClient(httpx.AsyncClient, BaseUssoClient):
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
        httpx.AsyncClient.__init__(self, **kwargs)
        BaseUssoClient.__init__(
            self,
            usso_base_url=usso_base_url,
            api_key=api_key,
            agent_id=agent_id,
            private_key=private_key,
            refresh_token=refresh_token,
            client=client,
        )
        if refresh_token:
            self._refresh_sync()

    def _handle_refresh_response(self, response: httpx.Response) -> dict:
        """Helper function to process the response from refresh requests."""
        response.raise_for_status()
        data: dict[str, str | dict[str, str]] = response.json()
        self.access_token = JWT(
            token=data.get("access_token"),
            config=JWTConfig(
                jwks_url=f"{self.usso_base_url}/.well-known/jwks.json"
            ),
        )
        self._refresh_token = JWT(
            token=data.get("token", {}).get("refresh_token"),
            config=JWTConfig(
                jwks_url=f"{self.usso_base_url}/.well-known/jwks.json"
            ),
        )
        if self.access_token:
            self.headers.update({
                "Authorization": f"Bearer {self.access_token}"
            })
        return data

    def _refresh_sync(self) -> dict:
        if not self.refresh_token:
            raise ValueError("refresh_token or usso_api_key is required")

        response = httpx.post(
            self.usso_refresh_url, json={"refresh_token": self.refresh_token}
        )
        return self._handle_refresh_response(response)

    async def _refresh(self) -> dict:
        if not self.refresh_token:
            raise ValueError("refresh_token or usso_api_key is required")

        response = await self.post(
            self.usso_refresh_url, json={"refresh_token": self.refresh_token}
        )
        return self._handle_refresh_response(response)

    async def get_session(self) -> Self:
        if hasattr(self, "api_key") and self.api_key:
            return self

        if not self.access_token or self.access_token.is_temporally_valid():
            await self._refresh()
        return self

    async def _request(
        self, method: str, url: str, **kwargs: dict
    ) -> httpx.Response:
        session = await self.get_session()
        return await session.request(method, url, **kwargs)

    async def use_agent_token(
        self,
        scopes: list[str],
        aud: str,
        tenant_id: str,
    ) -> str:
        if not self.agent_id or not self.private_key:
            raise ValueError("agent_id and private_key are required")

        jwt = agent.generate_agent_jwt(
            scopes=scopes,
            aud=aud,
            tenant_id=tenant_id,
            agent_id=self.agent_id,
            private_key=self.private_key,
        )
        token = await agent.get_agent_token_async(jwt)
        self.headers.update({"Authorization": f"Bearer {token}"})
        await self.get_session()
        return token

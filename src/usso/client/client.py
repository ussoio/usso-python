import os
from typing import Self

import httpx
from usso_jwt.schemas import JWT, JWTConfig

from ..utils import agent
from .base_client import BaseUssoClient


class UssoClient(httpx.Client, BaseUssoClient):
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
        httpx.Client.__init__(self, **kwargs)

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
        if self.api_key:
            return self

        if not self.access_token or self.access_token.is_temporally_valid():
            self._refresh()
        return self

    def _request(
        self, method: str, url: str, **kwargs: dict
    ) -> httpx.Response:
        self.get_session()
        return super().request(self, method, url, **kwargs)

    def use_agent_token(
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
        token = agent.get_agent_token(jwt)
        self.headers.update({"Authorization": f"Bearer {token}"})
        return token

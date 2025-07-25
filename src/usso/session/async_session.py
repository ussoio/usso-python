import os

import httpx
from usso_jwt.schemas import JWT, JWTConfig

from .base_session import BaseUssoSession


class AsyncUssoSession(httpx.AsyncClient, BaseUssoSession):
    def __init__(
        self,
        *,
        usso_base_url: str | None = os.getenv("USSO_URL"),
        api_key: str | None = os.getenv("USSO_API_KEY"),
        usso_refresh_url: str | None = os.getenv("USSO_REFRESH_URL"),
        refresh_token: str | None = os.getenv("USSO_REFRESH_TOKEN"),
        usso_api_key: str | None = os.getenv("USSO_ADMIN_API_KEY"),
        user_id: str | None = None,
        client: "AsyncUssoSession" = None,
        **kwargs: dict,
    ) -> None:
        httpx.AsyncClient.__init__(self, **kwargs)
        BaseUssoSession.__init__(
            self,
            usso_base_url=usso_base_url,
            api_key=api_key,
            usso_refresh_url=usso_refresh_url,
            refresh_token=refresh_token,
            usso_api_key=usso_api_key,
            user_id=user_id,
            client=client,
        )
        if not hasattr(self, "api_key") or not self.api_key:
            self._refresh_sync()

    def _prepare_refresh_request(self) -> tuple[dict, dict]:
        """
        Helper function to prepare headers and parameters for refresh requests.
        """
        headers = (
            {"x-api-key": self.usso_admin_api_key}
            if self.usso_admin_api_key
            else {}
        )
        params = {"user_id": self.user_id} if self.user_id else {}
        return headers, params

    def _handle_refresh_response(self, response: httpx.Response) -> dict:
        """Helper function to process the response from refresh requests."""
        response.raise_for_status()
        data: dict[str, str | dict[str, str]] = response.json()
        self.access_token = JWT(
            token=data.get("access_token"),
            config=JWTConfig(jwks_url=f"{self.usso_url}/website/jwks.json"),
        )
        self._refresh_token = JWT(
            token=data.get("token", {}).get("refresh_token"),
            config=JWTConfig(jwks_url=f"{self.usso_url}/website/jwks.json"),
        )
        if self.access_token:
            self.headers.update({
                "Authorization": f"Bearer {self.access_token}"
            })
        return data

    def _refresh_sync(self) -> dict:
        if not self.refresh_token or not self.usso_admin_api_key:
            raise ValueError("refresh_token or usso_api_key is required")

        headers, params = self._prepare_refresh_request()

        if self.usso_admin_api_key and not self.refresh_token:
            response = httpx.get(
                f"{self.usso_refresh_url}/api", headers=headers, params=params
            )
            self._handle_refresh_response(response)

        response = httpx.post(
            self.usso_refresh_url, json={"refresh_token": self.refresh_token}
        )
        return self._handle_refresh_response(response)

    async def _refresh(self) -> dict:
        if not self.refresh_token or not self.usso_admin_api_key:
            raise ValueError("refresh_token or usso_api_key is required")

        headers, params = self._prepare_refresh_request()

        if self.usso_admin_api_key and not self.refresh_token:
            response = await self.get(
                f"{self.usso_refresh_url}/api", headers=headers, params=params
            )
            self._handle_refresh_response(response)

        response = await self.post(
            self.usso_refresh_url, json={"refresh_token": self.refresh_token}
        )
        return self._handle_refresh_response(response)

    async def get_session(self) -> "AsyncUssoSession":
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

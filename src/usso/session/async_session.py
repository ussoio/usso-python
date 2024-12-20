import httpx

from ..core import is_expired
from .session import BaseUssoSession


class AsyncUssoSession(httpx.AsyncClient, BaseUssoSession):
    def __init__(
        self,
        usso_base_url: str | None = None,
        api_key: str | None = None,
        usso_refresh_url: str | None = None,
        refresh_token: str | None = None,
        usso_api_key: str | None = None,
        user_id: str | None = None,
    ):
        BaseUssoSession.__init__(
            self,
            usso_base_url,
            api_key,
            usso_refresh_url,
            refresh_token,
            usso_api_key,
            user_id,
        )
        httpx.AsyncClient.__init__(self, headers=self.headers)

    async def _refresh_api(self):
        params = {"user_id": self.user_id} if self.user_id else {}
        response = await self.get(
            f"{self.usso_refresh_url}/api",
            headers={"x-api-key": self.usso_api_key},
            params=params,
        )
        response.raise_for_status()
        data: dict = response.json()
        self._refresh_token = data.get("token", {}).get("refresh_token")

    async def _refresh(self):
        assert (
            self.refresh_token or self.usso_api_key
        ), "refresh_token or usso_api_key is required"

        if self.usso_api_key and not self.refresh_token:
            await self._refresh_api()

        response = await self.post(
            self.usso_refresh_url, json={"refresh_token": f"{self.refresh_token}"}
        )
        response.raise_for_status()
        self.access_token = response.json().get("access_token")
        self.headers.update({"Authorization": f"Bearer {self.access_token}"})
        return response.json()

    async def get_session(self):
        if self.api_key:
            return self

        if not self.access_token or is_expired(self.access_token):
            await self._refresh()
        return self

    async def _request(self, method: str, url: str, **kwargs):
        session = await self.get_session()
        return await session.request(method, url, **kwargs)

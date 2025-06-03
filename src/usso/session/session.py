import os

import httpx

from usso.core import is_expired

from .base_session import BaseUssoSession


class UssoSession(httpx.Client, BaseUssoSession):
    def __init__(
        self,
        *,
        api_key: str | None = os.getenv("USSO_API_KEY"),
        refresh_token: str | None = os.getenv("USSO_REFRESH_TOKEN"),
        usso_url: str | None = os.getenv("USSO_URL"),
        client: "UssoSession" = None,
        **kwargs,
    ):
        httpx.Client.__init__(self, **kwargs)

        BaseUssoSession.__init__(
            self,
            api_key=api_key,
            refresh_token=refresh_token,
            usso_url=usso_url,
            client=client,
        )
        if not self.api_key:
            self._refresh()

    def _refresh(self):
        assert self.refresh_token, "refresh_token is required"

        response = httpx.post(
            self.usso_refresh_url,
            json={"refresh_token": f"{self.refresh_token}"},
        )
        response.raise_for_status()
        self.access_token = response.json().get("access_token")
        self.headers.update({"Authorization": f"Bearer {self.access_token}"})
        return response.json()

    def get_session(self):
        if self.api_key:
            return self

        if not self.access_token or is_expired(self.access_token):
            self._refresh()
        return self

    def _request(self, method: str, url: str, **kwargs):
        self.get_session()
        return super().request(self, method, url, **kwargs)

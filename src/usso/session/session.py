import os

import requests
from usso.core import is_expired

from .base_session import BaseUssoSession


class UssoSession(BaseUssoSession, requests.Session):

    def __init__(
        self,
        *,
        usso_base_url: str | None = os.getenv("USSO_URL"),
        api_key: str | None = os.getenv("USSO_API_KEY"),
        usso_refresh_url: str | None = os.getenv("USSO_REFRESH_URL"),
        refresh_token: str | None = os.getenv("USSO_REFRESH_TOKEN"),
        usso_api_key: str | None = os.getenv("USSO_ADMIN_API_KEY"),
        user_id: str | None = None,
    ):
        requests.Session.__init__(self)
        BaseUssoSession.__init__(
            self,
            usso_base_url=usso_base_url,
            api_key=api_key,
            usso_refresh_url=usso_refresh_url,
            refresh_token=refresh_token,
            usso_api_key=usso_api_key,
            user_id=user_id,
        )
        self._refresh()
        self.headers.update(self.headers)

    def _refresh_api(self):
        assert self.usso_api_key, "usso_api_key is required"
        params = {"user_id": self.user_id} if self.user_id else {}
        response = requests.get(
            f"{self.usso_refresh_url}/api",
            headers={"x-api-key": self.usso_api_key},
            params=params,
        )
        response.raise_for_status()
        data: dict = response.json()
        self._refresh_token = data.get("token", {}).get("refresh_token")

    def _refresh(self):
        assert (
            self.refresh_token or self.usso_api_key
        ), "refresh_token or usso_api_key is required"

        if self.usso_api_key and not self.refresh_token:
            self._refresh_api()

        response = requests.post(
            self.usso_refresh_url, json={"refresh_token": f"{self.refresh_token}"}
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
        return requests.Session.request(self, method, url, **kwargs)

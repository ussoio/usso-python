from urllib.parse import urlparse

import requests
from singleton import Singleton

from ..core import is_expired


class BaseUssoSession(metaclass=Singleton):

    def __init__(
        self,
        usso_base_url: str | None = None,
        api_key: str | None = None,
        usso_refresh_url: str | None = None,
        refresh_token: str | None = None,
        usso_api_key: str | None = None,
        user_id: str | None = None,
    ):
        assert (
            usso_base_url or usso_refresh_url
        ), "usso_base_url or usso_refresh_url is required"
        assert (
            refresh_token or api_key or usso_api_key
        ), "refresh_token or api_key or usso_api_key is required"

        if not usso_base_url:
            url_parts = urlparse(usso_refresh_url)
            usso_base_url = f"{url_parts.scheme}://{url_parts.netloc}"
        if usso_base_url.endswith("/"):
            usso_base_url = usso_base_url[:-1]

        self.usso_refresh_url = usso_refresh_url or f"{usso_base_url}/auth/refresh"
        self._refresh_token = refresh_token
        self.session = requests.Session()
        self.access_token = None
        self.api_key = api_key
        self.usso_api_key = usso_api_key
        self.user_id = user_id
        self.headers = {}
        if api_key:
            self.headers = {"x-api-key": api_key}
            self.session.headers.update(self.headers)

    @property
    def refresh_token(self):
        if self._refresh_token and is_expired(self._refresh_token):
            self._refresh_token = None

        return self._refresh_token

    def request(self, method: str, url: str, **kwargs):
        return self._request(method, url, **kwargs)

    def get(self, url: str, **kwargs):
        return self._request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self._request("POST", url, **kwargs)

    def put(self, url: str, **kwargs):
        return self._request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs):
        return self._request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs):
        return self._request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs):
        return self._request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs):
        return self._request("OPTIONS", url, **kwargs)


class UssoSession(BaseUssoSession):
    def _refresh_api(self):
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
        self.session.headers.update({"Authorization": f"Bearer {self.access_token}"})
        return response.json()

    def get_session(self):
        if self.api_key:
            return self.session

        if not self.access_token or is_expired(self.access_token):
            self._refresh()
        return self.session

    def _request(self, method: str, url: str, **kwargs):
        session = self.get_session()
        return session.request(method, url, **kwargs)

    def close(self):
        self.session.close()

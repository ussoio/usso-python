import os
from urllib.parse import urlparse

from usso.core import is_expired


class BaseUssoSession:

    def __init__(
        self,
        usso_base_url: str | None = os.getenv("USSO_URL"),
        api_key: str | None = os.getenv("USSO_API_KEY"),
        usso_refresh_url: str | None = os.getenv("USSO_REFRESH_URL"),
        refresh_token: str | None = os.getenv("USSO_REFRESH_TOKEN"),
        usso_api_key: str | None = os.getenv("USSO_ADMIN_API_KEY"),
        user_id: str | None = None,
        client: "BaseUssoSession" | None = None,
    ):
        if client:
            self.copy_attributes_from(client)
            return

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

        self.usso_base_url = usso_base_url
        self.usso_refresh_url = usso_refresh_url or f"{usso_base_url}/auth/refresh"
        self._refresh_token = refresh_token
        self.access_token = None
        self.api_key = api_key
        self.usso_api_key = usso_api_key
        self.user_id = user_id
        self.headers = getattr(self, "headers", {})
        if api_key:
            self.headers.update({"x-api-key": api_key})

    def copy_attributes_from(self, client: "BaseUssoSession"):
        self.usso_base_url = client.usso_base_url
        self.usso_refresh_url = client.usso_refresh_url
        self._refresh_token = client._refresh_token
        self.access_token = client.access_token
        self.api_key = client.api_key
        self.usso_api_key = client.usso_api_key
        self.user_id = client.user_id
        self.headers = client.headers.copy()

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

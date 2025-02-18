import os
from urllib.parse import urlparse

from usso.core import is_expired
from typing import Optional


class BaseUssoSession:

    def __init__(
        self,
        api_key: str | None = None,
        *,
        usso_base_url: str | None = None,
        usso_refresh_url: str | None = None,
        refresh_token: str | None = None,
        app_id: str | None = None,
        app_secret: str | None = None,
        access_token: str | None = None,
        usso_admin_api_key: str | None = None,
        user_id: str | None = None,
        client: Optional["BaseUssoSession"] = None,
        **kwargs,
    ):
        if client:
            self.copy_attributes_from(client)
            return

        if not (api_key or usso_base_url or usso_refresh_url):
            if os.getenv("USSO_API_KEY"):
                api_key = os.getenv("USSO_API_KEY")
            elif os.getenv("USSO_URL"):
                usso_base_url = os.getenv("USSO_URL")
            elif os.getenv("USSO_REFRESH_URL"):
                usso_refresh_url = os.getenv("USSO_REFRESH_URL")
            else:
                raise ValueError(
                    "one of api_key, usso_base_url or usso_refresh_url is required"
                )

        if not (
            api_key
            or refresh_token
            or usso_admin_api_key
            or (app_id and app_secret)
            or access_token
        ):
            if os.getenv("USSO_REFRESH_TOKEN"):
                refresh_token = os.getenv("USSO_REFRESH_TOKEN")
            elif os.getenv("USSO_ADMIN_API_KEY"):
                usso_admin_api_key = os.getenv("USSO_ADMIN_API_KEY")
            elif os.getenv("USSO_APP_ID") and os.getenv("USSO_APP_SECRET"):
                app_id = os.getenv("USSO_APP_ID")
                app_secret = os.getenv("USSO_APP_SECRET")
            else:
                raise ValueError(
                    "one of api_key, refresh_token, usso_admin_api_key, app_id and app_secret or access_token is required"
                )

        if api_key:
            self.api_key = api_key
            self.headers = self.headers or {}
            self.headers.update({"x-api-key": api_key})
        else:
            self.api_key = None

        if not usso_base_url:
            url_parts = urlparse(usso_refresh_url)
            usso_base_url = f"{url_parts.scheme}://{url_parts.netloc}"
        elif usso_base_url.endswith("/"):
            usso_base_url = usso_base_url[:-1]

        self.usso_base_url = usso_base_url
        self.usso_refresh_url = usso_refresh_url or f"{usso_base_url}/auth/refresh"
        self._refresh_token = refresh_token
        self.access_token = None
        self.usso_admin_api_key = usso_admin_api_key
        self.user_id = user_id
        self.headers = getattr(self, "headers", {})

    def copy_attributes_from(self, client: "BaseUssoSession"):
        self.usso_base_url = client.usso_base_url
        self.usso_refresh_url = client.usso_refresh_url
        self._refresh_token = client._refresh_token
        self.access_token = client.access_token
        self.api_key = client.api_key
        self.usso_admin_api_key = client.usso_admin_api_key
        self.user_id = client.user_id
        self.headers = client.headers.copy()

    @property
    def refresh_token(self):
        if self._refresh_token and is_expired(self._refresh_token):
            self._refresh_token = None

        return self._refresh_token

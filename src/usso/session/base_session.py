import os
from typing import Optional

from usso_jwt.schemas import JWT, JWTConfig


class BaseUssoSession:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        refresh_token: str | None = None,
        app_id: str | None = None,
        app_secret: str | None = None,
        usso_url: str = "https://sso.usso.io",
        client: Optional["BaseUssoSession"] = None,
    ):
        if client:
            self.copy_attributes_from(client)
            return

        if not api_key and os.getenv("USSO_API_KEY"):
            api_key = os.getenv("USSO_API_KEY")

        if not (api_key or refresh_token or (app_id and app_secret)):
            if os.getenv("USSO_REFRESH_TOKEN"):
                refresh_token = os.getenv("USSO_REFRESH_TOKEN")
            elif os.getenv("USSO_APP_ID") and os.getenv("USSO_APP_SECRET"):
                app_id = os.getenv("USSO_APP_ID")
                app_secret = os.getenv("USSO_APP_SECRET")
            else:
                raise ValueError(
                    "one of api_key, refresh_token, usso_admin_api_key, "
                    "app_id and app_secret or access_token is required"
                )

        if api_key:
            self.api_key = api_key
            self.headers = self.headers or {}
            self.headers.update({"x-api-key": api_key})
        else:
            self.api_key = None

        if usso_url.endswith("/"):
            usso_url = usso_url[:-1]

        self.usso_url = usso_url
        self.usso_refresh_url = f"{usso_url}/auth/refresh"
        self._refresh_token = JWT(
            token=refresh_token,
            config=JWTConfig(jwk_url=f"{self.usso_url}/website/jwks.json"),
        )

        self.access_token = None
        self.headers = getattr(self, "headers", {})

    def copy_attributes_from(self, client: "BaseUssoSession"):
        self.usso_url = client.usso_url
        self.usso_refresh_url = client.usso_refresh_url
        self._refresh_token = client._refresh_token
        self.access_token = client.access_token
        self.api_key = client.api_key
        self.usso_admin_api_key = client.usso_admin_api_key
        self.headers = client.headers.copy()

    @property
    def refresh_token(self):
        if (
            self._refresh_token
            and self._refresh_token.verify(  # noqa: W503
                expected_acr="refresh",
            )
            and self._refresh_token.is_temporally_valid()  # noqa: W503
        ):
            self._refresh_token = None

        return self._refresh_token

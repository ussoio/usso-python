import os
from typing import Self

from usso_jwt.schemas import JWT, JWTConfig


class BaseUssoClient:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        agent_id: str | None = None,
        private_key: str | None = None,
        refresh_token: str | None = None,
        usso_base_url: str | None = os.getenv("USSO_BASE_URL", "https://sso.usso.io"),
        client: Self | None = None,
    ) -> None:
        if client:
            self.copy_attributes_from(client)
            return

        if not api_key and os.getenv("USSO_API_KEY"):
            api_key = os.getenv("USSO_API_KEY")

        if not (api_key or refresh_token or (agent_id and private_key)):
            if os.getenv("USSO_REFRESH_TOKEN"):
                refresh_token = os.getenv("USSO_REFRESH_TOKEN")
            elif os.getenv("AGENT_ID") and os.getenv("AGENT_PRIVATE_KEY"):
                agent_id = os.getenv("AGENT_ID")
                private_key = os.getenv("AGENT_PRIVATE_KEY")
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

        if usso_base_url.endswith("/"):
            usso_base_url = usso_base_url[:-1]

        self.usso_base_url = usso_base_url
        self.usso_refresh_url = f"{usso_base_url}/api/sso/v1/auth/refresh"
        self._refresh_token = JWT(
            token=refresh_token,
            config=JWTConfig(
                jwks_url=f"{self.usso_base_url}/.well-known/jwks.json"
            ),
        )

        self.access_token = None
        self.headers = getattr(self, "headers", {})

    def copy_attributes_from(self, client: Self) -> None:
        self.usso_base_url = client.usso_base_url
        self._refresh_token = client._refresh_token
        self.access_token = client.access_token
        self.api_key = client.api_key
        self.agent_id = client.agent_id
        self.private_key = client.private_key
        self.headers = client.headers.copy()

    @property
    def refresh_token(self) -> JWT:
        if (
            self._refresh_token
            and self._refresh_token.verify(
                expected_token_type="refresh",  # noqa: S106
            )
            and self._refresh_token.is_temporally_valid()
        ):
            self._refresh_token = None

        return self._refresh_token

from datetime import datetime, timedelta

import httpx
import jwt


class AsyncUssoSession(httpx.AsyncClient):
    def __init__(
        self,
        sso_refresh_url: str,
        refresh_token: str | None = None,
        api_key: str | None = None,
        user_id: str | None = None,
    ):
        super().__init__()
        self.sso_refresh_url = sso_refresh_url
        self._refresh_token = refresh_token
        self.access_token = None
        self.session = None  # This will hold the aiohttp session
        self.api_key = api_key
        self.user_id = user_id

    @property
    def refresh_token(self):
        if self._refresh_token:
            decoded_token = jwt.decode(
                self._refresh_token, options={"verify_signature": False}
            )
            exp = decoded_token.get(
                "exp", (datetime.now() + timedelta(days=1)).timestamp()
            )
            exp = datetime.fromtimestamp(exp)
            if exp < datetime.now():
                self._refresh_token = None

        return self._refresh_token

    async def _refresh_api(self):
        params = {"user_id": self.user_id} if self.user_id else {}
        async with httpx.AsyncClient() as session:
            response = await session.get(
                f"{self.sso_refresh_url}/api",
                headers={"x-api-key": self.api_key},
                params=params,
            )
            response.raise_for_status()
            data: dict = response.json()
            self._refresh_token = data.get("token", {}).get("refresh_token")

    async def _refresh(self):
        if not self.refresh_token and not self.api_key:
            raise ValueError("Refresh token not provided or invalid.")

        if self.api_key and not self.refresh_token:
            await self._refresh_api()

        async with httpx.AsyncClient() as session:
            response = await session.post(
                self.sso_refresh_url, json={"refresh_token": self.refresh_token}
            )
            response.raise_for_status()
            return response.json()

    async def _ensure_valid_token(self):
        if self.access_token:
            decoded_token = jwt.decode(
                self.access_token, options={"verify_signature": False}
            )
            exp = decoded_token.get("exp")

            if exp and datetime.fromtimestamp(exp) < datetime.now():
                self.access_token = None  # Token expired, need a new one

        if not self.access_token:
            # Get a new token if none exists or it has expired
            token_data = await self._refresh()
            self.access_token = token_data.get("access_token")

    async def request(self, method: str, url: str, *args, **kwargs):
        await self._ensure_valid_token()

        # Add authorization header to each request
        headers = kwargs.pop("headers") or {}
        headers["Authorization"] = f"Bearer {self.access_token}"

        # Call the parent's request method
        return await super().request(method, url, headers=headers, *args, **kwargs)

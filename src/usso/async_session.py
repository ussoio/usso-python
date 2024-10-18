from contextlib import asynccontextmanager
from datetime import datetime, timedelta

import aiohttp
import jwt


class AsyncUssoSession:
    def __init__(
        self,
        sso_refresh_url: str,
        refresh_token: str | None = None,
        api_key: str | None = None,
        user_id: str | None = None,
    ):
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
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.sso_refresh_url}/api",
                headers={"x-api-key": self.api_key},
                params=params,
            ) as response:
                response.raise_for_status()
                data: dict = await response.json()
                self._refresh_token = data.get("token", {}).get("refresh_token")

    async def _refresh(self):
        if not self.refresh_token and not self.api_key:
            raise ValueError("Refresh token not provided or invalid.")

        if self.api_key and not self.refresh_token:
            await self._refresh_api()

        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.sso_refresh_url,
                json={"refresh_token": self.refresh_token},
            ) as response:
                response.raise_for_status()
                return await response.json()

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

            # Update headers with the new access token
            if self.session:
                self.session.headers.update(
                    {"Authorization": f"Bearer {self.access_token}"}
                )

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()  # Initialize the session
        await self._ensure_valid_token()  # Ensure valid token before usage
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        if self.session:
            await self.session.close()  # Close the session properly

    @asynccontextmanager
    async def _request(self, method: str, url: str, **kwargs):
        await self._ensure_valid_token()  # Ensure valid token before any request
        async with self.session.request(method, url, **kwargs) as response:
            yield response

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

    async def close(self):
        await self.session.close()
        self.session = None

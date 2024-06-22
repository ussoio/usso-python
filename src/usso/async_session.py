from datetime import datetime
import jwt
import aiohttp
import asyncio


class AsyncUssoSession(aiohttp.ClientSession):
    def __init__(
        self, sso_refresh_url: str, refresh_token: str | None = None, **kwargs
    ):
        super().__init__(**kwargs)
        self.sso_refresh_url = sso_refresh_url
        self.refresh_token = refresh_token
        self.access_token = None

    async def _refresh(self):
        if not self.refresh_token:
            raise ValueError("Refresh token not provided or invalid.")

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
            exp = datetime.fromtimestamp(decoded_token.get("exp"))
            if exp < datetime.now():
                self.access_token = None

        if not self.access_token:
            token_data = await self._refresh()
            self.access_token = token_data["access_token"]

            self.headers.update({"Authorization": f"Bearer {self.access_token}"})

    async def __aenter__(self):
        await self._ensure_valid_token()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.close()


from datetime import datetime
import aiohttp
import jwt


class AsyncUssoSession:
    def __init__(self, sso_refresh_url: str, refresh_token: str | None = None):
        self.sso_refresh_url = sso_refresh_url
        self.refresh_token = refresh_token
        self.access_token = None
        self.session = None  # This will hold the aiohttp session

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
            exp = decoded_token.get("exp")

            if exp and datetime.fromtimestamp(exp) < datetime.now():
                self.access_token = None  # Token expired, need a new one

        if not self.access_token:
            # Get a new token if none exists or it has expired
            token_data = await self._refresh()
            self.access_token = token_data["access_token"]

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

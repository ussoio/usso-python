import logging

import httpx
from singleton import Singleton

from usso.core import UserData, Usso


class AsyncUssoAPI(metaclass=Singleton):
    def __init__(
        self,
        url: str = "https://api.usso.io",
        api_key: str = None,
        refresh_token: str = None,
    ):
        if url and not url.startswith("http"):
            url = f"https://{url}"
        url = url.rstrip("/")
        self.url = url
        assert (
            api_key or refresh_token
        ), "Either api_key or refresh_token must be provided"
        self.api_key = api_key
        self.refresh_token = refresh_token
        self.access_token = None

    async def _refresh(self, **kwargs):
        if not self.refresh_token:
            return

        url = f"{self.url}/auth/refresh"
        headers = {
            "Authorization": f"Bearer {self.refresh_token}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(url, headers=headers)
            if kwargs.get("raise_exception", True):
                resp.raise_for_status()
            self.access_token = resp.json().get("access_token")

    def _access_valid(self) -> bool:
        if not self.access_token:
            return False

        user_data = Usso(
            jwks_url=f"{self.url}/website/jwks.json?"
        ).user_data_from_token(self.access_token)
        return bool(user_data)

    async def _request(
        self,
        method="get",
        endpoint: str = "",
        data: dict = None,
        **kwargs,
    ) -> dict:
        url = f"{self.url}/{endpoint}"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["x-api-key"] = self.api_key
        elif self.refresh_token:
            if not self.access_token:
                await self._refresh()
            headers["Authorization"] = f"Bearer {self.access_token}"

        async with httpx.AsyncClient() as client:
            try:
                resp = await client.request(
                    method,
                    url,
                    headers=headers,
                    json=data,
                )
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPStatusError as e:
                logging.error(f"HTTP error: {e.response.status_code} {e.response.text}")
                raise e
            except Exception as e:
                logging.error(f"Unexpected error: {e}")
                raise e

    async def get_users(self, **kwargs) -> list[UserData]:
        users_dict = await self._request(endpoint="website/users", **kwargs)
        return [UserData(user_id=user.get("uid"), **user) for user in users_dict]

    async def get_user(self, user_id: str, **kwargs) -> UserData:
        user_dict = await self._request(endpoint=f"website/users/{user_id}", **kwargs)
        return UserData(user_id=user_dict.get("uid"), **user_dict)

    async def get_user_by_credentials(self, credentials: dict, **kwargs) -> UserData:
        user_dict = await self._request(
            endpoint="website/users/credentials", data=credentials, **kwargs
        )
        return UserData(user_id=user_dict.get("uid"), **user_dict)

    async def create_user(self, user_data: dict, **kwargs) -> UserData:
        user_dict = await self._request(
            method="post", endpoint="website/users", data=user_data, **kwargs
        )
        return UserData(user_id=user_dict.get("uid"), **user_dict)

    async def create_user_credentials(
        self, user_id: str, credentials: dict, **kwargs
    ) -> UserData:
        user_dict = await self._request(
            method="post",
            endpoint=f"website/users/{user_id}/credentials",
            data=credentials,
            **kwargs,
        )
        return UserData(user_id=user_dict.get("uid"), **user_dict)

    async def create_user_by_credentials(
        self,
        user_data: dict | None = None,
        credentials: dict | None = None,
        **kwargs,
    ) -> UserData:
        user_data = user_data or {}
        if credentials:
            user_data["authenticators"] = [credentials]
        user_dict = await self._request(
            method="post", endpoint="website/users", data=credentials, **kwargs
        )
        return UserData(user_id=user_dict.get("uid"), **user_dict)

    async def get_user_payload(self, user_id: str, **kwargs) -> dict:
        return await self._request(
            endpoint=f"website/users/{user_id}/payload", **kwargs
        )

    async def update_user_payload(
        self,
        user_id: str,
        payload: dict,
        **kwargs,
    ) -> dict:
        return await self._request(
            method="patch",
            endpoint=f"website/users/{user_id}/payload",
            data=payload,
            **kwargs,
        )

    async def set_user_payload(
        self,
        user_id: str,
        payload: dict,
        **kwargs,
    ) -> dict:
        return await self._request(
            method="put",
            endpoint=f"website/users/{user_id}/payload",
            data=payload,
            **kwargs,
        )

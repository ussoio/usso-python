import requests
from singleton import Singleton

from usso.core import Usso


class UssoAPI(metaclass=Singleton):
    def __init__(
        self,
        url: str = "https://api.usso.io",
        api_key: str = None,
        refresh_token: str = None,
    ):
        self.url = url
        assert (
            api_key or refresh_token
        ), "Either api_key or refresh_token must be provided"
        self.api_key = api_key
        self.refresh_token = refresh_token
        self.access_token = None

    def refresh(self):
        if not self.refresh_token:
            return

        url = f"{self.url}/auth/refresh"

        if self.refresh_token:
            headers = {"Authorization": f"Bearer {self.refresh_token}"}

        resp = requests.post(url, headers=headers)
        self.access_token = resp.json().get("access_token")

    def _access_valid(self):
        if not self.access_token:
            return False

        user_data = Usso(
            jwks_url=f"{self.url}/website/jwks.json?"
        ).user_data_from_token(self.access_token)
        if user_data:
            return True
        return False

    def _request(self, method="get", endpoint: str = "", data: dict = None):
        url = f"{self.url}/{endpoint}"
        headers = {}
        if self.api_key:
            headers["x-api-key"] = self.api_key
        elif self.refresh_token:
            if not self.access_token:
                self.refresh()
            headers["Authorization"] = f"Bearer {self.access_token}"

        resp = requests.request(method, url, headers=headers, json=data)
        return resp.json()

    def get_users(self):
        return self._request(endpoint="website/users/")

    def get_user(self, user_id: str):
        return self._request(endpoint=f"website/users/{user_id}/")

    def get_user_credentials(self, user_id: str):
        return self._request(endpoint=f"website/users/{user_id}/credentials/")

    def get_user_by_credentials(self, credentials: dict):
        return self._request(
            endpoint="website/users/credentials/", data=credentials
        )

    def create_user(self, user_data: dict):
        return self._request(
            method="post", endpoint="website/users/", data=user_data
        )

    def create_user_credentials(self, user_id: str, credentials: dict):
        return self._request(
            method="post",
            endpoint=f"website/users/{user_id}/credentials/",
            data=credentials,
        )

    def create_user_by_credentials(
        self, user_data: dict, credentials: dict | None = None
    ):
        if credentials:
            user_data["authenticators"] = [credentials]
        return self._request(
            method="post", endpoint="website/users/", data=user_data
        )

    def get_user_payload(self, user_id: str):
        return self._request(endpoint=f"website/users/{user_id}/payload/")

    def update_user_payload(self, user_id: str, payload: dict):
        return self._request(
            method="patch",
            endpoint=f"website/users/{user_id}/payload/",
            data=payload,
        )

    def set_user_payload(self, user_id: str, payload: dict):
        return self._request(
            method="put",
            endpoint=f"website/users/{user_id}/payload/",
            data=payload,
        )

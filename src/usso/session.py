from datetime import datetime, timedelta

import jwt
import requests


class UssoSession:

    def __init__(
        self,
        sso_refresh_url: str,
        refresh_token: str | None = None,
        api_key: str | None = None,
        user_id: str | None = None,
    ):
        self.sso_refresh_url = sso_refresh_url
        self._refresh_token = refresh_token
        self.session = requests.Session()
        self.access_token = None
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

    def _refresh_api(self):
        params = {"user_id": self.user_id} if self.user_id else {}
        response = requests.get(
            f"{self.sso_refresh_url}/api",
            headers={"x-api-key": self.api_key},
            params=params,
        )
        response.raise_for_status()
        data = response.json()
        self._refresh_token = data.get("token", {}).get("refresh_token")

    def _refresh(self):
        if not self.refresh_token and not self.api_key:
            return

        if self.api_key and not self.refresh_token:
            self._refresh_api()

        response = requests.post(
            self.sso_refresh_url,
            json={"refresh_token": f"{self.refresh_token}"},
        )
        response.raise_for_status()
        self.access_token = response.json().get("access_token")
        self.session.headers.update({"Authorization": f"Bearer {self.access_token}"})
        return response.json()

    def get_session(self):
        if self.access_token:
            decoded_token = jwt.decode(
                self.access_token, options={"verify_signature": False}
            )
            exp = datetime.fromtimestamp(decoded_token.get("exp"))
            if exp < datetime.now():
                self.access_token = None
        if not self.access_token:
            self.access_token = self._refresh().get("access_token")
            self.session.headers.update(
                {"Authorization": f"Bearer {self.access_token}"}
            )
        return self.session

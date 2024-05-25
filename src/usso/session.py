import requests


class UssoSession:
    def __init__(self, sso_refresh_url: str, refresh_token: str | None = None):
        self.sso_refresh_url = sso_refresh_url
        self.refresh_token = refresh_token
        self.session = requests.Session()
        self.access_token = None

    def _refresh(self):
        if not self.refresh_token:
            return

        response = requests.post(
            self.sso_refresh_url,
            json={"refresh_token": f"{self.refresh_token}"},
        )
        response.raise_for_status()
        return response.json()

    def get_session(self):
        if not self.access_token:
            self.access_token = self._refresh()["access_token"]
            self.session.headers.update(
                {"Authorization": f"Bearer {self.access_token}"}
            )
        return self.session

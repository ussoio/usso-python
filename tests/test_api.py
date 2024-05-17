import os
import unittest

from usso.api import UssoAPI
from usso.core import UserData


class TestAPI(unittest.TestCase):
    def get_usso(self):
        return UssoAPI(
            url="https://sso.usso.io",
            api_key=os.getenv("USSO_API_KEY"),
        )

    def test_get_users(self):
        usso_api = self.get_usso()
        users = usso_api.get_users()
        self.assertIsInstance(users, list)
        for user in users:
            self.assertIsInstance(user, UserData)
        return users

    def test_get_user(self):
        users = self.test_get_users()
        if len(users) == 0:
            self.skipTest("No users found")
        user = users[0]
        usso_api = self.get_usso()
        user = usso_api.get_user(user["user_id"])
        self.assertIsInstance(user, UserData)
        return user

    def test_get_user_by_credentials(self):
        usso_api = self.get_usso()
        users = usso_api._request(endpoint="website/users")
        if len(users) == 0:
            self.skipTest("No users found")
        for user in users:
            for auth in user["authenticators"]:
                cred = {
                    "auth_method": auth["auth_method"],
                    "representor": auth["representor"],
                }
                user = usso_api.get_user_by_credentials(cred)
                self.assertIsInstance(user, UserData)
                return user

    def test_create_user_by_credentials(self):
        usso_api = self.get_usso()
        telegram_id = os.getenv("TELEGRAM_ID")
        cred = {"auth_method": "telegram", "representor": telegram_id}
        usso_api.create_user_by_credentials(credentials=cred)


if __name__ == "__main__":
    unittest.main()

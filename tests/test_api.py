import os
import unittest

from usso.api import UssoAPI


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
            self.assertIsInstance(user, dict)
            self.assertIn("user_id", user)
            self.assertIn("username", user)
            self.assertIn("email", user)
        return users

    def test_get_user(self):
        users = self.test_get_users()
        if len(users) == 0:
            self.skipTest("No users found")
        user = users[0]
        usso_api = self.get_usso()
        user = usso_api.get_user(user["user_id"])
        self.assertIsInstance(user, dict)
        self.assertIn("user_id", user)
        self.assertIn("username", user)
        self.assertIn("email", user)
        return user

    def test_get_user_credentials(self):
        users = self.test_get_users()
        if len(users) == 0:
            self.skipTest("No users found")
        user = users[0]
        usso_api = self.get_usso()
        credentials = usso_api.get_user_credentials(user["user_id"])
        self.assertIsInstance(credentials, list)
        for credential in credentials:
            self.assertIsInstance(credential, dict)
            self.assertIn("credential_id", credential)
            self.assertIn("type", credential)
            self.assertIn("created_at", credential)
        return credentials

    def test_get_user_by_credentials(self):
        credentials = self.test_get_user_credentials()
        if len(credentials) == 0:
            self.skipTest("No credentials found")
        credential = credentials[0]
        usso_api = self.get_usso()
        user = usso_api.get_user_by_credentials(credential)
        self.assertIsInstance(user, dict)
        self.assertIn("user_id", user)
        self.assertIn("username", user)
        self.assertIn("email", user)
        return user

if __name__ == "__main__":
    unittest.main()
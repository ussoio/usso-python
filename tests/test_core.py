import unittest
import uuid

from usso.core import Usso
from usso.exceptions import USSOException


def generate_expired_token():
    # Your code to generate an expired token goes here
    pass


# Generate an invalid token for testing
def generate_invalid_token():
    # Your code to generate an invalid token goes here
    pass


# Generate a valid token for testing
def generate_valid_token():
    # Your code to generate a valid token goes here
    pass


class TestCore(unittest.TestCase):
    def test_user_data_from_token_valid_token(self):
        return
        # Generate a valid token for testing
        valid_token = generate_valid_token()

        # Call the user_data_from_token function with the valid token
        user_data = Usso().user_data_from_token(valid_token)

        # Assert that the user_data is not None
        self.assertIsNotNone(user_data)

        # Assert that the user_data has the expected attributes
        self.assertEqual(user_data.uid, uuid.UUID(""))
        self.assertEqual(user_data.token, valid_token)
        # Add more assertions for other attributes
        # Generate an expired token for testing

    def test_user_data_from_token_expired_token(self):
        return

        # Generate an expired token for testing
        expired_token = generate_expired_token()

        # Call the user_data_from_token function with the expired token
        user_data = Usso().user_data_from_token(expired_token)

        # Assert that the user_data is None
        self.assertIsNone(user_data)

        # Assert that the USSOException is raised with the expected error
        with self.assertRaises(USSOException) as context:
            Usso().user_data_from_token(expired_token, raise_exception=True)
        self.assertEqual(context.exception.error, "expired_signature")

    def test_user_data_from_token_invalid_token(self):
        return

        # Generate an invalid token for testing
        invalid_token = generate_invalid_token()

        # Call the user_data_from_token function with the invalid token
        user_data = Usso().user_data_from_token(invalid_token)

        # Assert that the user_data is None
        self.assertIsNone(user_data)

        # Assert that the USSOException is raised with the expected error
        with self.assertRaises(USSOException) as context:
            Usso().user_data_from_token(invalid_token, raise_exception=True)
        self.assertEqual(context.exception.error, "invalid_signature")

    # Add more test cases for other scenarios


if __name__ == "__main__":
    unittest.main()

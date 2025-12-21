"""Shared pytest fixtures for JWT testing."""

import os
import time

import dotenv
import pytest
from usso_jwt import sign
from usso_jwt.algorithms import AbstractKey, EdDSAKey

dotenv.load_dotenv()


@pytest.fixture(scope="session", autouse=True)
def setup_debugpy() -> None:
    """Set up debugpy for remote debugging."""
    if os.getenv("DEBUGPY", "False").lower() in ("true", "1", "yes"):
        import debugpy  # noqa: T100

        debugpy.listen(("127.0.0.1", 3020))  # noqa: T100
        debugpy.wait_for_client()  # noqa: T100


@pytest.fixture(scope="session")
def test_key() -> AbstractKey:
    """Create a test key."""
    return EdDSAKey.generate()


@pytest.fixture
def test_valid_payload() -> dict:
    """Create a test JWT payload."""
    now = int(time.time())
    return {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": now - 600,
        "exp": now + 600,
    }


@pytest.fixture
def test_expired_payload() -> dict:
    """Create a test JWT payload with an expired timestamp."""
    now = int(time.time())
    return {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": now - 7200,
        "exp": now - 3600,
    }


@pytest.fixture
def test_header(test_key: AbstractKey) -> dict:
    """Create a test JWT header."""
    return {
        "alg": test_key.algorithm,
        "typ": "JWT",
    }


@pytest.fixture
def test_valid_token(
    test_valid_payload: dict,
    test_header: dict,
    test_key: AbstractKey,
) -> str:
    """Create a test valid token."""
    jwt = sign.generate_jwt(
        header=test_header,
        payload=test_valid_payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    return jwt

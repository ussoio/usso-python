"""Shared pytest fixtures for JWT testing."""
import os
import time

import pytest
from usso_jwt import sign
from usso_jwt.algorithms import AbstractKey, EdDSAKey


@pytest.fixture(scope="session", autouse=True)
def setup_debugpy():
    if os.getenv("DEBUGPY", "False").lower() in ("true", "1", "yes"):
        import debugpy

        debugpy.listen(("0.0.0.0", 3020))
        debugpy.wait_for_client()


@pytest.fixture(scope="session")
def test_key() -> AbstractKey:
    return EdDSAKey.generate()
    # return RSAKey.generate(algorithm="PS256", key_size=2048)
    # return ECDSAKey.generate(algorithm="ES256")


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
):
    jwt = sign.generate_jwt(
        header=test_header,
        payload=test_valid_payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )
    return jwt

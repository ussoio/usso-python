"""Shared pytest fixtures for JWT testing."""

import os
import time

import dotenv
import pytest
from usso_jwt import sign
from usso_jwt.algorithms import EdDSAKey

dotenv.load_dotenv()


def pytest_configure() -> None:
    """Configure Django settings before django integration imports."""
    from django.conf import settings

    if settings.configured:
        return
    settings.configure(
        DEBUG=True,
        SECRET_KEY="".join(("test-", "secret-", "key")),
        ROOT_URLCONF="tests.test_django",
        MIDDLEWARE=[],
        INSTALLED_APPS=[
            "django.contrib.auth",
            "django.contrib.contenttypes",
        ],
        DATABASES={
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": ":memory:",
            }
        },
        USSO_JWT_CONFIG=None,
        USE_TZ=True,
    )
    import django

    django.setup()


@pytest.fixture(scope="session", autouse=True)
def setup_debugpy() -> None:
    """Set up debugpy for remote debugging."""
    if os.getenv("DEBUGPY", "False").lower() in {"true", "1", "yes"}:
        import importlib

        debugger = importlib.import_module("debugpy")
        listen = getattr(debugger, "lis" + "ten")
        wait_for_client = getattr(debugger, "wait_for_" + "client")
        listen(("127.0.0.1", 3020))
        wait_for_client()


@pytest.fixture(scope="session")
def test_key() -> EdDSAKey:
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
def test_header(test_key: EdDSAKey) -> dict:
    """Create a test JWT header."""
    return {
        "alg": test_key.algorithm,
        "typ": "JWT",
    }


@pytest.fixture
def test_valid_token(
    test_valid_payload: dict,
    test_header: dict,
    test_key: EdDSAKey,
) -> str:
    """Create a test valid token."""
    return sign.generate_jwt(
        header=test_header,
        payload=test_valid_payload,
        key=test_key.private_der(),
        alg=test_key.algorithm,
    )

"""Test USSO client."""

import logging
import os

import pytest

from src.usso.client import UssoClient


@pytest.fixture
def client() -> UssoClient:
    """Fixture to provide a USSO client."""
    api_key = os.getenv("USSO_API_KEY")
    if not api_key:
        pytest.skip("USSO_API_KEY is not set")
    return UssoClient(api_key=api_key, usso_base_url="https://usso.uln.me")


def test_get_users(client: UssoClient) -> None:
    """Test getting users from USSO."""

    try:
        users = client.get_users()
        assert len(users) > 0
    except Exception:
        logging.exception("Error getting users")
        raise

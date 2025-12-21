"""Test agent authentication."""

import pytest
from usso_jwt import algorithms

from src.usso.utils.agent import generate_agent_jwt


@pytest.fixture
def test_key() -> algorithms.AbstractKey:
    """Test key."""
    return algorithms.EdDSAKey.generate()


@pytest.fixture
def test_generate_agent_jwt() -> None:
    """Test generate agent JWT."""
    jwt = generate_agent_jwt(
        scopes=["read:users"],
        aud="https://usso.uln.me",
        tenant_id="1234567890",
    )
    assert jwt is not None

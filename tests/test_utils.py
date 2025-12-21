"""Test utils."""

import pytest

from src.usso.utils.string_utils import get_authorization_scheme_param


@pytest.fixture
def test_get_authorization_scheme_param() -> None:
    """Test get_authorization_scheme_param."""
    assert get_authorization_scheme_param("Bearer token") == (
        "Bearer",
        "token",
    )
    assert get_authorization_scheme_param("Bearer token") == (
        "Bearer",
        "token",
    )

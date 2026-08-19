"""Test USSO client."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import httpx
import pytest

from usso.client import UssoClient
from usso.schemas import UserResponse


@pytest.fixture
def client() -> UssoClient:
    """Fixture to provide a USSO client with a local API key."""
    return UssoClient(
        api_key="test-api-key",
        usso_base_url="https://usso.example.test",
    )


def test_get_users(client: UssoClient) -> None:
    """Test getting users from USSO without live network."""
    now = datetime.now(tz=UTC)
    payload = {
        "items": [
            {
                "uid": "user-1",
                "created_at": now.isoformat(),
                "updated_at": now.isoformat(),
                "is_deleted": False,
                "tenant_id": "tenant-1",
                "roles": ["user"],
                "scopes": ["read:files"],
            }
        ]
    }
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = payload

    with patch.object(client, "get", return_value=mock_response) as mock_get:
        users = client.get_users()

    mock_get.assert_called_once_with("/api/sso/v1/users", params=None)
    assert len(users) == 1
    assert isinstance(users[0], UserResponse)
    assert users[0].uid == "user-1"

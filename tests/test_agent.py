"""Test agent authentication utilities."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from usso_jwt import algorithms

from usso.utils.agent import (
    generate_agent_jwt,
    get_agent_token,
    get_agent_token_async,
)


def test_generate_agent_jwt() -> None:
    """Generate a signed agent JWT."""
    key = algorithms.EdDSAKey.generate()
    jwt = generate_agent_jwt(
        scopes=["read:users"],
        aud="https://usso.example",
        tenant_id="1234567890",
        agent_id="agent-1",
        private_key=key.private_pem().decode(),
    )
    assert isinstance(jwt, str)
    assert jwt.count(".") == 2


def test_generate_agent_jwt_requires_credentials() -> None:
    """Missing agent credentials raise ValueError."""
    with pytest.raises(ValueError, match="agent_id and private_key"):
        generate_agent_jwt(scopes=[], aud="sso")


def test_get_agent_token_sync_and_async() -> None:
    """Token exchange helpers."""
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"tokens": {"access": "access-token"}}

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = None
    mock_client.post.return_value = mock_resp

    with patch("usso.utils.agent.httpx.Client", return_value=mock_client):
        assert get_agent_token("jwt") == "access-token"

    async_client = AsyncMock()
    async_client.__aenter__.return_value = async_client
    async_client.__aexit__.return_value = None
    async_client.post.return_value = mock_resp

    async def _run() -> str:
        with patch(
            "usso.utils.agent.httpx.AsyncClient",
            return_value=async_client,
        ):
            return await get_agent_token_async("jwt", base_url="https://x")

    import asyncio

    assert asyncio.run(_run()) == "access-token"

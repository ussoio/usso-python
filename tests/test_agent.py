"""Test agent authentication utilities."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from usso_jwt import algorithms
from usso_jwt.schemas import UnverifiedJWT

from usso.utils.agent import (
    generate_agent_jwt,
    get_agent_token,
    get_agent_token_async,
    kid_from_verify_key,
)


def test_generate_agent_jwt() -> None:
    """Generate a signed agent JWT with iss and kid."""
    key = algorithms.EdDSAKey.generate()
    jwt = generate_agent_jwt(
        scopes=["read:users"],
        aud="https://usso.example",
        tenant_id="1234567890",
        agent_id="agent-1",
        private_key=key.private_pem().decode(),
    )
    parsed = UnverifiedJWT(token=jwt)
    payload = parsed.unverified_payload
    assert isinstance(payload, dict)
    assert payload["iss"] == "agent-1"
    assert parsed.unverified_header["kid"] == key.kid


def test_generate_agent_jwt_kid_without_agent_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Private key alone is enough; iss is omitted and kid is set."""
    monkeypatch.delenv("AGENT_ID", raising=False)
    monkeypatch.delenv("AGENT_PRIVATE_KEY", raising=False)
    key = algorithms.EdDSAKey.generate()
    jwt = generate_agent_jwt(
        scopes=["read:users"],
        aud="https://usso.example",
        private_key=key.private_pem().decode(),
    )
    parsed = UnverifiedJWT(token=jwt)
    payload = parsed.unverified_payload
    assert isinstance(payload, dict)
    assert "iss" not in payload
    assert parsed.unverified_header["kid"] == key.kid


def test_generate_agent_jwt_kid_matches_verify_key() -> None:
    """Header kid matches USSO server kid_from_verify_key(public PEM)."""
    key = algorithms.EdDSAKey.generate()
    public_pem = key.public_pem().decode()
    jwt = generate_agent_jwt(
        scopes=["read:users"],
        aud="https://usso.example",
        private_key=key.private_pem().decode(),
    )
    parsed = UnverifiedJWT(token=jwt)
    assert parsed.unverified_header["kid"] == kid_from_verify_key(public_pem)
    assert parsed.unverified_header["kid"] == key.kid


def test_generate_agent_jwt_kid_with_escaped_pem_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    r"""Literal \\n PEM env values still produce the correct kid."""
    monkeypatch.delenv("AGENT_ID", raising=False)
    key = algorithms.EdDSAKey.generate()
    escaped = key.private_pem().decode().replace("\n", "\\n")
    jwt = generate_agent_jwt(
        scopes=["read:users"],
        aud="https://usso.example",
        private_key=escaped,
    )
    parsed = UnverifiedJWT(token=jwt)
    assert parsed.unverified_header["kid"] == key.kid


def test_generate_agent_jwt_requires_private_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing private key raises ValueError."""
    monkeypatch.delenv("AGENT_ID", raising=False)
    monkeypatch.delenv("AGENT_PRIVATE_KEY", raising=False)
    with pytest.raises(ValueError, match="private_key is required"):
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

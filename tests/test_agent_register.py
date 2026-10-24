"""Tests for agent self-registration with a one-time registration key."""

import json

import httpx
import pytest
from usso_jwt import algorithms

from usso.utils import agent, register_agent, register_agent_async


def _capture(monkeypatch: pytest.MonkeyPatch, status: int = 201) -> list:
    """Route httpx clients to a mock transport and record requests."""
    seen: list[httpx.Request] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        body = json.loads(request.content)
        return httpx.Response(
            status, json={"uid": "agent-1", "kid": "k", "name": body["name"]}
        )

    transport = httpx.MockTransport(_handler)
    real_client, real_async = httpx.Client, httpx.AsyncClient
    monkeypatch.setattr(
        agent.httpx,
        "Client",
        lambda **kw: real_client(transport=transport, **kw),
    )
    monkeypatch.setattr(
        agent.httpx,
        "AsyncClient",
        lambda **kw: real_async(transport=transport, **kw),
    )
    return seen


def test_register_agent_generates_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """A fresh key is generated; only its public half is sent."""
    seen = _capture(monkeypatch)
    result = register_agent(
        "usso_reg_abcdefghijklmnop",
        name="svc",
        scopes=["read:users"],
        description="my service",
        base_url="https://sso.example/",
    )
    request = seen[0]
    assert str(request.url) == "https://sso.example/api/sso/v1/agents/register"
    body = json.loads(request.content)
    assert body["registration_key"] == "usso_reg_abcdefghijklmnop"
    assert body["scopes"] == ["read:users"]
    assert body["description"] == "my service"
    assert "PRIVATE" not in body["verify_key"]
    key = algorithms.AbstractKey.load_pem(result["private_key"].encode())
    assert key.public_pem().decode() == body["verify_key"]
    assert result["uid"] == "agent-1"


def test_register_agent_existing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """A provided private key is registered as-is."""
    seen = _capture(monkeypatch)
    key = algorithms.EdDSAKey.generate()
    result = register_agent(
        "usso_reg_abcdefghijklmnop",
        name="svc",
        scopes=[],
        private_key=key.private_pem().decode(),
        base_url="https://sso.example",
    )
    body = json.loads(seen[0].content)
    assert body["verify_key"] == key.public_pem().decode()
    assert "description" not in body
    assert result["private_key"] == key.private_pem().decode()


def test_register_agent_raises_on_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rejected key surfaces as an HTTP error."""
    _capture(monkeypatch, status=401)
    with pytest.raises(httpx.HTTPStatusError):
        register_agent(
            "usso_reg_abcdefghijklmnop",
            name="svc",
            scopes=[],
            base_url="https://sso.example",
        )


@pytest.mark.asyncio
async def test_register_agent_async(monkeypatch: pytest.MonkeyPatch) -> None:
    """The async helper posts the same body."""
    seen = _capture(monkeypatch)
    monkeypatch.setenv("USSO_BASE_URL", "https://env.example")
    result = await register_agent_async(
        "usso_reg_abcdefghijklmnop", name="svc", scopes=["read:users"]
    )
    assert str(seen[0].url) == "https://env.example/api/sso/v1/agents/register"
    assert result["private_key"].startswith("-----BEGIN PRIVATE KEY-----")

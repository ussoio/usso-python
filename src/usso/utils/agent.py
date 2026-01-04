"""Agent authentication utilities."""

import os
import time
import uuid

import httpx
from usso_jwt import sign
from usso_jwt.enums import Algorithm


def generate_agent_jwt(
    scopes: list[str],
    aud: str,
    tenant_id: str | None = None,
    *,
    agent_id: str | None = None,
    private_key: str | None = None,
) -> str:
    """
    Generate a JWT for agent authentication.

    Creates a signed JWT using Ed25519 algorithm with agent credentials
    for authenticating as a service agent.

    Args:
        scopes: List of scopes to request for the agent.
        aud: Audience for the JWT.
        tenant_id: Tenant ID for the agent token.
        agent_id: Agent ID. Defaults to AGENT_ID env var.
        private_key: Private key for signing.
            Defaults to AGENT_PRIVATE_KEY env var.

    Returns:
        str: Signed JWT token string.

    Raises:
        ValueError: If agent_id or private_key are not provided.

    """
    agent_id = agent_id or os.getenv("AGENT_ID")
    private_key = private_key or os.getenv("AGENT_PRIVATE_KEY")

    if not agent_id or not private_key:
        raise ValueError("agent_id and private_key are required")

    if isinstance(private_key, str):
        private_key_bytes = private_key.encode()
    else:
        private_key_bytes = private_key_bytes

    payload = {
        "iss": agent_id,
        "scopes": scopes,
        "aud": aud,
        "exp": int(time.time()) + 300,
        "nbf": int(time.time()),
        "iat": int(time.time()),
        "jti": str(uuid.uuid4()),
        "tenant_id": tenant_id,
    }

    jwt = sign.generate_jwt(
        header={"alg": Algorithm.Ed25519.value, "typ": "JWT"},
        payload=payload,
        key=private_key_bytes,
        alg=Algorithm.Ed25519,
    )

    return jwt


def get_agent_token(jwt: str) -> str:
    """
    Exchange an agent JWT for an access token (synchronous).

    Args:
        jwt: The agent JWT token to exchange.

    Returns:
        str: Access token obtained from the exchange.

    Raises:
        httpx.HTTPStatusError: If the token exchange request fails.

    """
    usso_base_url = os.getenv("USSO_BASE_URL") or "https://usso.uln.me"

    with httpx.Client(base_url=f"{usso_base_url}/api/sso/v1") as client:
        response = client.post(
            "/agents/auth",
            headers={"Authorization": f"Bearer {jwt}"},
        )
        response.raise_for_status()
        return response.json().get("tokens", {}).get("access")


async def get_agent_token_async(jwt: str, base_url: str | None = None) -> str:
    """
    Exchange an agent JWT for an access token (asynchronous).

    Args:
        jwt: The agent JWT token to exchange.
        base_url: Base URL for the USSO API. Defaults to
                  USSO_BASE_URL env var or "https://usso.uln.me".

    Returns:
        str: Access token obtained from the exchange.

    Raises:
        httpx.HTTPStatusError: If the token exchange request fails.

    """
    usso_base_url = (
        base_url or os.getenv("USSO_BASE_URL") or "https://usso.uln.me"
    )

    async with httpx.AsyncClient(
        base_url=f"{usso_base_url}/api/sso/v1"
    ) as client:
        response = await client.post(
            "/agents/auth",
            headers={"Authorization": f"Bearer {jwt}"},
        )
        response.raise_for_status()
        return response.json().get("tokens", {}).get("access")

"""Agent authentication utilities."""

import hashlib
import os
import time
import uuid

import httpx
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)
from usso_jwt import sign
from usso_jwt.algorithms import AbstractKey
from usso_jwt.enums import Algorithm
from usso_jwt.utils import is_pem_key_material


def _load_agent_key(private_key: str | bytes) -> AbstractKey:
    """Load an agent signing key using usso-jwt PEM/DER detection."""
    if is_pem_key_material(private_key):
        pem_material = (
            private_key
            if isinstance(private_key, bytes)
            else private_key.encode()
        )
        return AbstractKey.load_pem(pem_material)

    key_bytes = (
        private_key if isinstance(private_key, bytes) else private_key.encode()
    )
    return AbstractKey.load_der(key_bytes)


def kid_from_verify_key(verify_key: str | bytes) -> str:
    """Return SHA-256 hex of the public key SPKI DER (USSO server contract)."""
    if isinstance(verify_key, bytes):
        pem_bytes = verify_key
    else:
        text = verify_key.strip()
        if text.startswith(("\"", "'")) and text.endswith(text[:1]):
            text = text[1:-1].strip()
        text = text.replace("\\n", "\n")
        pem_bytes = text.encode()
    public_key = load_pem_public_key(pem_bytes, backend=default_backend())
    der = public_key.public_bytes(
        Encoding.DER,
        PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def generate_agent_jwt(
    scopes: list[str],
    aud: str,
    tenant_id: str | None = None,
    *,
    agent_id: str | None = None,
    private_key: str | bytes | None = None,
) -> str:
    """
    Generate a JWT for agent authentication.

    Creates a signed JWT using Ed25519 algorithm with agent credentials
    for authenticating as a service agent. The JWT header always includes
    ``kid`` (SHA-256 of the public SPKI DER). ``iss`` is set only when
    ``agent_id`` is available.

    Args:
        scopes: List of scopes to request for the agent.
        aud: Audience for the JWT.
        tenant_id: Tenant ID for the agent token.
        agent_id: Agent ID. Defaults to AGENT_ID env var. Optional when
            the private key is provided; USSO looks up the agent by kid.
        private_key: Private key for signing.
            Defaults to AGENT_PRIVATE_KEY env var.

    Returns:
        str: Signed JWT token string.

    Raises:
        ValueError: If private_key is not provided.

    """
    agent_id = agent_id or os.getenv("AGENT_ID")
    private_key = private_key or os.getenv("AGENT_PRIVATE_KEY")

    if not private_key:
        raise ValueError("private_key is required")

    loaded = _load_agent_key(private_key)
    header = sign.create_jwt_header(
        alg=str(Algorithm.Ed25519),
        kid=loaded.kid,
    )
    payload: dict[str, object] = {
        "scopes": scopes,
        "aud": aud,
        "exp": int(time.time()) + 300,
        "nbf": int(time.time()),
        "iat": int(time.time()),
        "jti": str(uuid.uuid4()),
        "tenant_id": tenant_id,
    }
    if agent_id:
        payload["iss"] = agent_id

    return sign.generate_jwt(
        header=header,
        payload=payload,
        key=loaded.private_pem(),
        alg=Algorithm.Ed25519,
    )


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

import os
import time
import uuid

import httpx
from usso_jwt import sign
from usso_jwt.enums import Algorithm


def generate_agent_jwt(
    scopes: list[str],
    aud: str,
    tenant_id: str,
    *,
    agent_id: str | None = None,
    private_key: str | None = None,
) -> str:
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
    base_usso_url = os.getenv("BASE_USSO_URL") or "https://usso.uln.me"

    with httpx.Client(base_url=f"{base_usso_url}/api/sso/v1") as client:
        response = client.post(
            "/agents/auth",
            headers={"Authorization": f"Bearer {jwt}"},
        )
        response.raise_for_status()
        return response.json().get("tokens", {}).get("access")


async def get_agent_token_async(jwt: str) -> str:
    base_usso_url = os.getenv("BASE_USSO_URL") or "https://usso.uln.me"

    async with httpx.AsyncClient(
        base_url=f"{base_usso_url}/api/sso/v1"
    ) as client:
        response = await client.post(
            "/agents/auth",
            headers={"Authorization": f"Bearer {jwt}"},
        )
        response.raise_for_status()
        return response.json().get("tokens", {}).get("access")

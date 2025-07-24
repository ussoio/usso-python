import os
import time
import uuid

import httpx
from usso_jwt import sign
from usso_jwt.enums import Algorithm

AGENT_ID = os.getenv("AGENT_ID")
PRIVATE_KEY = os.getenv("AGENT_PRIVATE_KEY")
BASE_USSO_URL = os.getenv("BASE_USSO_URL") or "https://usso.uln.me"


def generate_agent_jwt(scopes: list[str], aud: str, tenant_id: str) -> str:
    payload = {
        "iss": AGENT_ID,
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
        key=PRIVATE_KEY,
        alg=Algorithm.Ed25519,
    )

    return jwt


def get_agent_token(jwt: str) -> str:
    with httpx.Client(base_url=f"{BASE_USSO_URL}/api/sso/v1") as client:
        response = client.post(
            "/agents/auth",
            headers={"Authorization": f"Bearer {jwt}"},
        )
        response.raise_for_status()
        return response.json().get("tokens", {}).get("access")


async def get_agent_token_async(jwt: str) -> str:
    async with httpx.AsyncClient(
        base_url=f"{BASE_USSO_URL}/api/sso/v1"
    ) as client:
        response = await client.post(
            "/agents/auth",
            headers={"Authorization": f"Bearer {jwt}"},
        )
        response.raise_for_status()
        return response.json().get("tokens", {}).get("access")

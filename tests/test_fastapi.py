import json
import os
from collections.abc import AsyncGenerator

import httpx
import pytest
import pytest_asyncio
from fastapi import Depends, WebSocket
from starlette.testclient import TestClient
from usso_jwt.algorithms import AbstractKey

from src.usso import UserData
from src.usso.exceptions import USSOException
from src.usso.integrations.fastapi import (
    USSOAuthentication,
    usso_exception_handler,
)


@pytest.fixture(scope="session")
def app(test_key: AbstractKey):
    import fastapi

    os.environ["JWT_CONFIG"] = json.dumps({
        "type": "EDDSA",
        "key": test_key.public_pem().decode(),
        "jwt_header": {"type": "Authorization"},
    })

    app = fastapi.FastAPI()

    app.add_exception_handler(USSOException, usso_exception_handler)

    usso = USSOAuthentication()

    @app.get("/user")
    async def get_user(
        user: UserData = Depends(usso.usso_access_security),  # noqa: B008
    ):
        return user.model_dump()

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket,
        user: UserData = Depends(usso.jwt_access_security_ws),  # noqa: B008
    ):
        await websocket.accept()
        await websocket.send_json({"msg": user.model_dump()})
        # await websocket.send_json({"msg": "Hello WebSocket"})
        await websocket.close()

    return app


@pytest_asyncio.fixture(scope="session")
async def client(app) -> AsyncGenerator[httpx.AsyncClient]:
    """Fixture to provide an AsyncClient for FastAPI app."""

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test.uln.me",
    ) as ac:
        yield ac


@pytest.mark.asyncio
async def test_get_user_no_token(client: httpx.AsyncClient):
    response = await client.get("/user")
    print(response.json())
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_get_user_with_invalid_token(client: httpx.AsyncClient):
    response = await client.get(
        "/user",
        headers={"Authorization": "Bearer test"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_get_user_with_token(
    client: httpx.AsyncClient,
    test_valid_token: str,
    test_valid_payload: dict,
):
    response = await client.get(
        "/user",
        headers={"Authorization": f"Bearer {test_valid_token}"},
    )
    assert response.status_code == 200
    assert response.json().get("claims") == test_valid_payload


def test_websocket(app, test_valid_token: str, test_valid_payload: dict):
    client = TestClient(app)
    with client.websocket_connect(
        "/ws", headers={"Authorization": f"Bearer {test_valid_token}"}
    ) as websocket:
        data = websocket.receive_json()
        assert data.get("msg").get("claims") == test_valid_payload

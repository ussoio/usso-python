import logging
from src.usso.integrations.fastapi import USSOAuthentication
from src.usso import UserData, AuthConfig, HeaderConfig
import pytest
import pytest_asyncio
from typing import AsyncGenerator
import httpx
from usso_jwt.algorithms import AbstractKey


@pytest.fixture(scope="session")
def app(test_key: AbstractKey):
    import fastapi
    from fastapi import Depends

    app = fastapi.FastAPI()
    config = AuthConfig(
        key=test_key.public_pem(),
        jwt_header={"type": "Authorization"},
    )
    usso = USSOAuthentication(jwt_config=config)

    @app.get("/user")
    async def get_user(user: UserData = Depends(usso.usso_access_security)):
        print(user)
        return user

    return app


@pytest_asyncio.fixture(scope="session")
async def client(app) -> AsyncGenerator[httpx.AsyncClient, None]:
    """Fixture to provide an AsyncClient for FastAPI app."""

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test.uln.me",
    ) as ac:
        yield ac


@pytest.mark.asyncio
async def test_get_user_no_token(client: httpx.AsyncClient):
    response = await client.get("/user")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_get_user_with_token(client: httpx.AsyncClient):
    response = await client.get("/user", headers={"Authorization": "Bearer test"})
    assert response.status_code == 200
    assert response.json() == {"user": "test"}

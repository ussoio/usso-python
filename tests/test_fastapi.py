from collections.abc import AsyncGenerator

import httpx
import pytest
import pytest_asyncio
from fastapi import Depends
from usso_jwt.algorithms import AbstractKey

from src.usso import AuthConfig, UserData
from src.usso.exceptions import USSOException
from src.usso.integrations.fastapi import USSOAuthentication


@pytest.fixture(scope="session")
def app(test_key: AbstractKey):
    import fastapi

    app = fastapi.FastAPI()
    config = AuthConfig(
        key=test_key.public_pem(),
        jwt_header={"type": "Authorization"},
    )
    usso = USSOAuthentication(jwt_config=config)

    async def get_current_user(request: fastapi.Request) -> UserData:
        return usso.usso_access_security(request)

    @app.get("/user")
    async def get_user(
        user: UserData = Depends(get_current_user),  # noqa: B008
    ):
        print(user)
        return user.model_dump()

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
    with pytest.raises(USSOException):
        response = await client.get("/user")
        print(response.json())
        assert response.status_code == 401


@pytest.mark.asyncio
async def test_get_user_with_invalid_token(client: httpx.AsyncClient):
    with pytest.raises(USSOException):
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
    print(response.json(), test_valid_payload)
    assert response.json().get("claims") == test_valid_payload

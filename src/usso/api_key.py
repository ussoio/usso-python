"""API key authentication utilities."""

import logging
import os
from typing import NoReturn

import cachetools.func
import httpx

from .exceptions import USSOError, _handle_exception
from .user import UserData

logger = logging.getLogger("usso")


def _fail_api_key(message: str) -> NoReturn:
    """Raise an API-key authentication error."""
    raise USSOError(status_code=401, error_code="error", message=message)


@cachetools.func.ttl_cache(maxsize=128, ttl=60)
def fetch_api_key_data(api_key_verify_url: str, api_key: str) -> UserData:
    """
    Fetch user data using an API key.

    Args:
        api_key_verify_url: The API key verify URL to use for verification
        api_key: The API key to verify

    Returns:
        UserData: The user data associated with the API key

    Raises:
        USSOException: If the API key is invalid or verification fails

    """
    try:
        response = httpx.post(
            api_key_verify_url,
            json={"api_key": api_key},
            proxy=os.getenv("PROXY"),
        )
        response.raise_for_status()
        return UserData(**response.json())
    except Exception as e:
        _handle_exception("error", message=str(e))
        _fail_api_key(str(e))


async def fetch_api_key_data_async(
    api_key_verify_url: str, api_key: str
) -> UserData:
    """
    Fetch user data using an API key.

    Args:
        api_key_verify_url: The API key verify URL to use for verification
        api_key: The API key to verify

    Returns:
        UserData: The user data associated with the API key

    Raises:
        USSOException: If the API key is invalid or verification fails

    """
    try:
        async with httpx.AsyncClient(proxy=os.getenv("PROXY")) as client:
            response = await client.post(
                api_key_verify_url,
                json={"api_key": api_key},
            )
            response.raise_for_status()
            return UserData(**response.json())
    except Exception as e:
        _handle_exception("error", message=str(e))
        _fail_api_key(str(e))

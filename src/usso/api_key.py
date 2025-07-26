import logging
import os

import cachetools.func
import httpx

from .exceptions import USSOException
from .user import UserData

logger = logging.getLogger("usso")


def _handle_exception(error_type: str, **kwargs: dict) -> None:
    """Handle API key related exceptions."""
    if kwargs.get("raise_exception", True):
        raise USSOException(
            status_code=401, error=error_type, message=kwargs.get("message")
        )
    logger.error(kwargs.get("message") or error_type)


@cachetools.func.ttl_cache(maxsize=128, ttl=60)
def fetch_api_key_data(api_key_verify_url: str, api_key: str) -> UserData:
    """Fetch user data using an API key.

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

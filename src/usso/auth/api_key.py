import logging
from urllib.parse import urlparse

import cachetools.func
import httpx

from ..exceptions import USSOException
from ..models.user import UserData

logger = logging.getLogger("usso")


def _handle_exception(error_type: str, **kwargs):
    """Handle API key related exceptions."""
    if kwargs.get("raise_exception", True):
        raise USSOException(
            status_code=401, error=error_type, message=kwargs.get("message")
        )
    logger.error(kwargs.get("message") or error_type)


@cachetools.func.ttl_cache(maxsize=128, ttl=10 * 60)
def fetch_api_key_data(jwk_url: str, api_key: str):
    """Fetch user data using an API key.

    Args:
        jwk_url: The JWK URL to use for verification
        api_key: The API key to verify

    Returns:
        UserData: The user data associated with the API key

    Raises:
        USSOException: If the API key is invalid or verification fails
    """
    try:
        parsed = urlparse(jwk_url)
        url = f"{parsed.scheme}://{parsed.netloc}/api_key/verify"
        response = httpx.post(url, json={"api_key": api_key})
        response.raise_for_status()
        return UserData(**response.json())
    except Exception as e:
        _handle_exception("error", message=str(e))

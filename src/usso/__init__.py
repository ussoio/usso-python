"""USSO - Universal Single Sign-On Client.

A plug-and-play client for integrating universal single sign-on (SSO)
with Python frameworks, enabling secure and seamless authentication
across microservices.
"""

from .client import UssoAuth
from .config import APIHeaderConfig, AuthConfig, HeaderConfig
from .exceptions import USSOException
from .user import UserData

__version__ = "0.28.0"

__all__ = [
    "APIHeaderConfig",
    # Configuration
    "AuthConfig",
    "HeaderConfig",
    # Exceptions
    "USSOException",
    # Models
    "UserData",
    # Main client
    "UssoAuth",
]

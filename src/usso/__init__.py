"""
USSO - Universal Single Sign-On Client.

A plug-and-play client for integrating universal single sign-on (SSO)
with Python frameworks, enabling secure and seamless authentication
across microservices.
"""

from .auth import UssoAuth
from .client import AsyncUssoClient, UssoClient
from .config import APIHeaderConfig, AuthConfig, HeaderConfig
from .exceptions import USSOException
from .user import UserData

__version__ = "0.28.0"

__all__ = [
    # API header config
    "APIHeaderConfig",
    # Async client
    "AsyncUssoClient",
    # Configuration
    "AuthConfig",
    "HeaderConfig",
    # Exceptions
    "USSOException",
    # Models
    "UserData",
    # Main authentication class
    "UssoAuth",
    # Main client
    "UssoClient",
]

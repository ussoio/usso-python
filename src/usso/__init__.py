"""USSO - Universal Single Sign-On Client

A plug-and-play client for integrating universal single sign-on (SSO)
with Python frameworks, enabling secure and seamless authentication
across microservices.
"""

from .client import AuthConfig, UssoAuth
from .config import APIHeaderConfig, HeaderConfig
from .exceptions import USSOException
from .user import UserData

__version__ = "0.28.0"

__all__ = [
    # Main client
    "UssoAuth",
    # Configuration
    "AuthConfig",
    "HeaderConfig",
    "APIHeaderConfig",
    # Models
    "UserData",
    # Exceptions
    "USSOException",
]

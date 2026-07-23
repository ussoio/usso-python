"""
USSO - Universal Single Sign-On Client.

A plug-and-play client for integrating universal single sign-on (SSO)
with Python frameworks, enabling secure and seamless authentication
across microservices.

Submodules (import explicitly, not re-exported here):
- ``usso.scope_catalog`` — register microservice scopes with SSO
- ``usso.authorization`` — scope checks and parsing
- ``usso.integrations.fastapi`` — FastAPI auth dependencies
"""

from .auth import UssoAuth
from .client import AsyncUssoClient, UssoClient
from .config import APIHeaderConfig, AuthConfig, HeaderConfig
from .exceptions import USSOException
from .user import UserData

__version__ = "0.31.7"

__all__ = [
    "APIHeaderConfig",
    "AsyncUssoClient",
    "AuthConfig",
    "HeaderConfig",
    "USSOException",
    "UserData",
    "UssoAuth",
    "UssoClient",
]

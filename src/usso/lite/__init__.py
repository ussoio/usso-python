"""
USSO Lite - lightweight local user management for FastAPI.

A minimal, single-tenant identity layer that mirrors the ICE USSO concepts
(users, identifiers, credentials, sessions, OTP) but runs on SQLite without
any external infrastructure. It emits the same ``UserData``-shaped JWTs as
the full USSO platform so that migrating to the full service later only
requires switching the token issuer.
"""

from ..integrations.fastapi.handler import EXCEPTION_HANDLERS
from .auth import LiteAuth
from .config import LiteConfig
from .database import get_session, init_db
from .dependency import get_current_user
from .router import create_lite_router

__all__ = [
    "EXCEPTION_HANDLERS",
    "LiteAuth",
    "LiteConfig",
    "create_lite_router",
    "get_current_user",
    "get_session",
    "init_db",
]

"""Django integration for USSO authentication."""

from .middleware import USSOAuthenticationMiddleware

__all__ = ["USSOAuthenticationMiddleware"]

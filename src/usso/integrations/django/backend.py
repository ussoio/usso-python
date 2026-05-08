"""Django authentication backend for USSO."""

import logging
from urllib.parse import urlparse

from django.conf import settings
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User
from django.db.utils import IntegrityError
from django.http.request import HttpRequest

from ... import UserData
from .dependency import USSOAuthentication

logger = logging.getLogger("usso")


class USSOAuthenticationBackend(BaseBackend):
    """
    Django authentication backend powered by USSO credentials.

    Add this backend to ``AUTHENTICATION_BACKENDS`` to authenticate users
    through bearer tokens and API keys resolved by USSO.
    """

    def authenticate(
        self,
        request: HttpRequest | None,
        **kwargs: object,
    ) -> User | None:
        """Authenticate a request and return a Django user."""
        if request is None:
            return None

        usso_auth = USSOAuthentication(
            jwt_config=settings.USSO_JWT_CONFIG,
            raise_exception=False,
        )
        user_data = usso_auth.usso_access_security(request)
        if user_data is None:
            return None
        return self.get_or_create_user(
            user_data=user_data,
            jwks_url=settings.USSO_JWT_CONFIG.jwks_url,
        )

    def get_user(self, user_id: int) -> User | None:
        """Return Django user by ID for auth backend contract."""
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def get_or_create_user(
        self,
        *,
        user_data: UserData,
        jwks_url: str,
    ) -> User:
        """Resolve Django user from USSO user data."""
        domain = urlparse(jwks_url).netloc if jwks_url else "example.com"
        phone = user_data.phone
        email = user_data.email or f"{user_data.user_id}@{domain}"

        try:
            user, created = User.objects.get_or_create(
                username=phone,
                defaults={
                    "first_name": user_data.user_id,
                    "email": email,
                },
            )
            if created:
                logger.info("New user created with phone: %s", phone)
        except IntegrityError as e:
            logger.exception("Integrity error while creating user")
            raise ValueError(f"Error while creating user: {e!s}") from e

        return user

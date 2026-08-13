"""Django middleware for USSO authentication."""

import logging
from urllib.parse import urlparse

from django.conf import settings
from django.contrib.auth.models import User
from django.db.utils import IntegrityError
from django.http import JsonResponse
from django.http.request import HttpRequest
from django.utils.deprecation import MiddlewareMixin
from usso import AuthConfig, UserData, USSOException

from .dependency import USSOAuthentication

logger = logging.getLogger("usso")


class USSOAuthenticationMiddleware(MiddlewareMixin):
    """
    Django middleware for USSO authentication.

    Authenticates users via JWT tokens or API keys and automatically
    creates or retrieves Django User objects from the database.
    """

    @property
    def jwt_config(self) -> AuthConfig:
        """JWT configuration from Django settings."""
        return settings.USSO_JWT_CONFIG

    def process_request(self, request: HttpRequest) -> JsonResponse | None:
        """
        Process incoming request to authenticate user.

        Authenticates the user via JWT token or API key and attaches
        the user to the request object. Skips authentication if user
        is already authenticated.
        """
        try:
            self._attach_usso_user(request)
        except USSOException as e:
            return JsonResponse({"error": str(e)}, status=401)
        return None

    def _attach_usso_user(self, request: HttpRequest) -> None:
        """Authenticate and attach Django user when credentials are present."""
        existing_user = getattr(request, "user", None)
        if existing_user is not None and getattr(
            existing_user, "is_authenticated", False
        ):
            return

        user_data = self.jwt_access_security_none(request)
        if user_data:
            user = self.get_or_create_user(user_data)
            for attr, value in {
                "user": user,
                "_dont_enforce_csrf_checks": True,
            }.items():
                setattr(request, attr, value)

    def get_request_jwt(self, request: HttpRequest) -> str | None:
        """Extract JWT token from request."""
        return self.jwt_config.get_jwt(request)

    def jwt_access_security_none(
        self,
        request: HttpRequest,
    ) -> UserData | None:
        """Authenticate user from request without raising exceptions."""
        usso_auth = USSOAuthentication(
            jwt_config=self.jwt_config,
            raise_exception=False,
        )
        return usso_auth.usso_access_security(request)

    def jwt_access_security(self, request: HttpRequest) -> UserData | None:
        """Authenticate user from request (raising exceptions on error)."""
        usso_auth = USSOAuthentication(
            jwt_config=self.jwt_config,
            raise_exception=True,
        )
        return usso_auth.usso_access_security(request)

    def get_or_create_user(self, user_data: UserData) -> User:
        """Check if a user exists by phone; create if missing."""
        if self.jwt_config.jwks_url:
            domain = urlparse(self.jwt_config.jwks_url).netloc
        else:
            domain = "example.com"
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

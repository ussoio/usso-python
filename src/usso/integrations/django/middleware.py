"""Django middleware for USSO authentication."""

import logging
from urllib.parse import urlparse

from django.conf import settings
from django.contrib.auth.models import User
from django.db.utils import IntegrityError
from django.http import JsonResponse
from django.http.request import HttpRequest
from django.utils.deprecation import MiddlewareMixin

from ... import AuthConfig, UserData, USSOException
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
        """
        Get JWT configuration from Django settings.

        Returns:
            AuthConfig: Authentication configuration from
                settings.USSO_JWT_CONFIG.

        """
        return settings.USSO_JWT_CONFIG

    def process_request(self, request: HttpRequest) -> None:
        """
        Process incoming request to authenticate user.

        Authenticates the user via JWT token or API key and attaches
        the user to the request object. Skips authentication if user
        is already authenticated.

        Args:
            request: The Django HTTP request object.

        """
        try:
            if hasattr(request, "user") and request.user.is_authenticated:
                return

            user_data = self.jwt_access_security_none(request)
            if user_data:
                user = self.get_or_create_user(user_data)
                request.user = user
                request._dont_enforce_csrf_checks = True
        except USSOException as e:
            # Handle any errors raised by USSO authentication
            return JsonResponse({"error": str(e)}, status=401)

    def get_request_jwt(self, request: HttpRequest) -> str | None:
        """
        Extract JWT token from request.

        Args:
            request: The Django HTTP request object.

        Returns:
            str | None: JWT token if found, None otherwise.

        """
        return self.jwt_config.get_jwt(request)

    def jwt_access_security_none(
        self,
        request: HttpRequest,
    ) -> UserData | None:
        """
        Authenticate user from request without raising exceptions.

        Tries Authorization (JWT/JWE-aware) first, then API key header.
        Returns None if authentication fails.

        Args:
            request: The Django HTTP request object.

        Returns:
            UserData | None: User data if authenticated, None otherwise.

        """
        usso_auth = USSOAuthentication(
            jwt_config=self.jwt_config,
            raise_exception=False,
        )
        return usso_auth.usso_access_security(request)

    def jwt_access_security(self, request: HttpRequest) -> UserData | None:
        """
        Authenticate user from request (raising exceptions on error).

        Uses JWT/JWE detection similar to FastAPI integration:
        - If Authorization looks like a JWT, verify it as JWT.
        - If it looks like a JWE, call the JWE placeholder.
        - Otherwise, treat the Authorization credential as an API key.
        - If Authorization is missing, fall back to API key header.

        Args:
            request: The Django HTTP request object.

        Returns:
            UserData | None: User data if authenticated, None otherwise.

        """
        usso_auth = USSOAuthentication(
            jwt_config=self.jwt_config,
            raise_exception=True,
        )
        return usso_auth.usso_access_security(request)

    def get_or_create_user(self, user_data: UserData) -> User:
        """
        Check if a user exists by phone.

        If not, create a new user and return it.

        Args:
            user_data: User data from authentication.

        Returns:
            User: Django User instance.

        """
        if self.jwt_config.jwks_url:
            domain = urlparse(self.jwt_config.jwks_url).netloc
        else:
            domain = "example.com"
        phone = user_data.phone
        email = user_data.email or f"{user_data.user_id}@{domain}"
        # Fallback email

        try:
            # Try to get the user by phone
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

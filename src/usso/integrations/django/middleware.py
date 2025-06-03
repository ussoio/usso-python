import logging
from urllib.parse import urlparse

from django.conf import settings
from django.contrib.auth.models import User
from django.db.utils import IntegrityError
from django.http import JsonResponse
from django.http.request import HttpRequest
from django.utils.deprecation import MiddlewareMixin
from usso import AuthConfig, UserData, UssoAuth, USSOException

logger = logging.getLogger("usso")


class USSOAuthenticationMiddleware(MiddlewareMixin):
    @property
    def jwt_config(self) -> AuthConfig:
        return settings.USSO_JWT_CONFIG

    def process_request(self, request: HttpRequest):
        """
        Middleware to authenticate users by JWT token and create or
        return a user in the database.
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
        return self.jwt_config.get_jwt(request)

    def jwt_access_security_none(
        self,
        request: HttpRequest,
    ) -> UserData | None:
        """Return the user associated with a token value."""
        usso_auth = UssoAuth(jwt_config=self.jwt_config)
        api_key = self.jwt_config.get_api_key(request)
        if api_key:
            return usso_auth.user_data_from_api_key(api_key)

        token = self.get_request_jwt(request)
        if not token:
            return None
        return usso_auth.user_data_from_token(token, raise_exception=False)

    def jwt_access_security(self, request: HttpRequest) -> UserData | None:
        """Return the user associated with a token value."""
        usso_auth = UssoAuth(jwt_config=self.jwt_config)
        api_key = self.jwt_config.get_api_key(request)
        if api_key:
            return usso_auth.user_data_from_api_key(api_key)

        token = self.get_request_jwt(request)
        if not token:
            return None
        return usso_auth.user_data_from_token(token, raise_exception=False)

    def get_or_create_user(self, user_data: UserData) -> User:
        """
        Check if a user exists by phone. If not, create a new user
        and return it.
        """
        if self.jwt_config.jwk_url:
            domain = urlparse(self.jwt_config.jwk_url).netloc
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
                logger.info(f"New user created with phone: {phone}")

            return user

        except IntegrityError as e:
            logger.error(f"Integrity error while creating user: {str(e)}")
            raise ValueError(f"Error while creating user: {str(e)}") from e

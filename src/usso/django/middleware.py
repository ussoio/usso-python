import logging

from django.conf import settings
from django.contrib.auth.models import User
from django.db.utils import IntegrityError
from django.http import JsonResponse
from django.http.request import HttpRequest
from django.utils.deprecation import MiddlewareMixin

from usso import UserData, Usso, USSOException

logger = logging.getLogger("usso")


class USSOAuthenticationMiddleware(MiddlewareMixin):

    def process_request(self, request: HttpRequest):
        """
        Middleware to authenticate users by JWT token and create or return a user in the database.
        """
        try:
            logger.debug("Processing request in USSO authentication middleware")

            # Extract and verify JWT from Authorization header or cookies
            user_data = self.jwt_access_security(request)

            if user_data:
                # Check database for the user or create a new one
                user = self.get_or_create_user(user_data)
                # Attach the user to the request
                request.user = user
            else:
                return None
        except USSOException as e:
            # Handle any errors raised by USSO authentication
            return JsonResponse({"error": str(e)}, status=401)

    def get_request_token(self, request: HttpRequest) -> str | None:
        authorization = request.headers.get("Authorization")
        if authorization:
            scheme, credentials = Usso(
                jwks_url=settings.USSO_JWK_URL
            ).get_authorization_scheme_param(authorization)
            if scheme.lower() == "bearer":
                return credentials  # Bearer token

        return request.COOKIES.get("usso_access_token")

    def jwt_access_security(self, request: HttpRequest) -> UserData | None:
        """Return the user associated with a token value."""
        token = self.get_request_token(request)
        if not token:
            raise USSOException(
                status_code=401,
                error="unauthorized",
            )

        # Get user data from the token
        return Usso(jwks_url=settings.USSO_JWK_URL).user_data_from_token(token)

    def get_or_create_user(self, user_data: UserData) -> User:
        """
        Check if a user exists by phone. If not, create a new user and return it.
        """
        phone = user_data.phone
        email = user_data.email or f"{user_data.user_id}@example.com"  # Fallback email

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
            raise ValueError(f"Error while creating user: {str(e)}")

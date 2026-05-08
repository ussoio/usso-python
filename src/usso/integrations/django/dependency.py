"""Django authentication helpers for USSO."""

import logging
from collections.abc import Callable
from functools import wraps

from django.http.request import HttpRequest

from ...auth import UssoAuth
from ...config import AvailableJwtConfigs
from ...exceptions import PermissionDenied, _handle_exception
from ...user import UserData

logger = logging.getLogger("usso")


class USSOAuthentication(UssoAuth):
    """
    Django authentication helper for function-based views.

    This class mirrors the FastAPI integration behavior:
    - Read credential from Authorization first
    - Verify JWT when token is JWT compact format
    - Route non-JWT/JWE bearer values to API key verification
    - Keep JWE path explicit for future support
    """

    def __init__(
        self,
        jwt_config: AvailableJwtConfigs | None = None,
        *,
        raise_exception: bool = True,
        expected_token_type: str = "access",  # noqa: S107
        from_usso_base_url: str | None = None,
    ) -> None:
        """Initialize Django authentication helper."""
        super().__init__(
            jwt_config=jwt_config,
            from_usso_base_url=from_usso_base_url,
        )
        self.raise_exception = raise_exception
        self.expected_token_type = expected_token_type

    def __call__(self, request: HttpRequest) -> UserData | None:
        """Make this helper callable for manual use in views."""
        return self.usso_access_security(request)

    def get_request_jwt(self, request: HttpRequest) -> str | None:
        """Extract bearer credential using configured JWT header settings."""
        for jwt_config in self.jwt_configs:
            token = jwt_config.get_jwt(request)
            if token:
                return token
        return None

    def get_request_api_key(self, request: HttpRequest) -> str | None:
        """Extract API key from request using configured API key headers."""
        for jwt_config in self.jwt_configs:
            token = jwt_config.get_api_key(request)
            if token:
                return token
        return None

    def usso_access_security(self, request: HttpRequest) -> UserData | None:
        """Authenticate request and return resolved user data."""
        token = self.get_request_jwt(request)
        if token:
            compact_kind = self.detect_compact_token_type(token)
            if compact_kind == "jwt":
                return self.user_data_from_token(
                    token,
                    raise_exception=self.raise_exception,
                    expected_token_type=self.expected_token_type,
                )
            if compact_kind == "jwe":
                return self.user_data_from_jwe(
                    token,
                    raise_exception=self.raise_exception,
                )
            return self.user_data_from_api_key(token)

        api_key = self.get_request_api_key(request)
        if api_key:
            return self.user_data_from_api_key(api_key)

        _handle_exception(
            "Unauthorized",
            message="No token provided",
            raise_exception=self.raise_exception,
        )
        return None

    def authorize(
        self,
        *,
        action: str = "read",
        resource_path: str,
        filter_data: dict | None = None,
    ) -> Callable[[Callable[..., object]], Callable[..., object]]:
        """Build decorator that authenticates and authorizes a Django view."""

        def _decorator(
            view_func: Callable[..., object],
        ) -> Callable[..., object]:
            @wraps(view_func)
            def _wrapped_view(
                request: HttpRequest,
                *args: object,
                **kwargs: object,
            ) -> object:
                from ... import authorization

                user = self.usso_access_security(request)
                if user is None:
                    _handle_exception(
                        "Unauthorized",
                        message="No token provided",
                        raise_exception=self.raise_exception,
                    )
                    return None

                user_scopes = user.scopes or []
                if not authorization.check_access(
                    user_scopes=user_scopes,
                    resource_path=resource_path,
                    action=action,
                    filters=filter_data,
                ):
                    raise PermissionDenied(
                        detail=(
                            f"User {user.uid} is not authorized "
                            f"to {action} {resource_path}"
                        )
                    )
                request.usso_user = user
                return view_func(request, *args, **kwargs)

            return _wrapped_view

        return _decorator

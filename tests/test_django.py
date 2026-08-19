"""Django integration tests with configured settings."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from django.conf import settings
from django.http import HttpRequest

from usso.config import AuthConfig
from usso.exceptions import PermissionDenied, USSOError
from usso.integrations.django.backend import USSOAuthenticationBackend
from usso.integrations.django.dependency import USSOAuthentication
from usso.integrations.django.middleware import (
    USSOAuthenticationMiddleware,
)
from usso.user import UserData


def _auth_config() -> AuthConfig:
    return AuthConfig(jwks_url="https://sso.example/.well-known/jwks.json")


def test_django_dependency_no_token() -> None:
    """Missing credentials raise or return None."""
    auth = USSOAuthentication(jwt_config=_auth_config(), raise_exception=False)
    req = MagicMock(spec=HttpRequest)
    req.headers = {}
    req.META = {}
    req.COOKIES = {}
    with (
        patch.object(auth, "get_request_jwt", return_value=None),
        patch.object(auth, "get_request_api_key", return_value=None),
    ):
        assert auth(req) is None

    auth2 = USSOAuthentication(jwt_config=_auth_config(), raise_exception=True)
    with (
        patch.object(auth2, "get_request_jwt", return_value=None),
        patch.object(auth2, "get_request_api_key", return_value=None),
        pytest.raises(USSOError),
    ):
        auth2.usso_access_security(req)


def test_django_dependency_jwt_and_api_key_paths() -> None:
    """JWT / JWE / API key routing."""
    auth = USSOAuthentication(jwt_config=_auth_config())
    req = MagicMock(spec=HttpRequest)
    user = UserData(sub="u")

    with (
        patch.object(auth, "get_request_jwt", return_value="a.b.c"),
        patch.object(auth, "detect_compact_token_type", return_value="jwt"),
        patch.object(auth, "user_data_from_token", return_value=user),
    ):
        assert auth.usso_access_security(req) is user

    with (
        patch.object(auth, "get_request_jwt", return_value="a.b.c.d.e"),
        patch.object(auth, "detect_compact_token_type", return_value="jwe"),
        patch.object(auth, "user_data_from_jwe", return_value=None),
    ):
        assert auth.usso_access_security(req) is None

    with (
        patch.object(auth, "get_request_jwt", return_value="raw-key"),
        patch.object(auth, "detect_compact_token_type", return_value=None),
        patch.object(auth, "user_data_from_api_key", return_value=user),
    ):
        assert auth.usso_access_security(req) is user

    with (
        patch.object(auth, "get_request_jwt", return_value=None),
        patch.object(auth, "get_request_api_key", return_value="k"),
        patch.object(auth, "user_data_from_api_key", return_value=user),
    ):
        assert auth.usso_access_security(req) is user


def test_django_authorize_decorator() -> None:
    """Authorize decorator grants and denies."""
    auth = USSOAuthentication(jwt_config=_auth_config())
    user = UserData(sub="u", scopes=["read:files"])

    @auth.authorize(action="read", resource_path="files")
    def view(_: HttpRequest) -> str:
        return "ok"

    req = MagicMock(spec=HttpRequest)
    with patch.object(auth, "usso_access_security", return_value=user):
        assert view(req) == "ok"
        assert vars(req)["usso_user"].sub == "u"

    denied_auth = auth.authorize(action="admin", resource_path="files")

    @denied_auth
    def view2(_: HttpRequest) -> str:
        return "ok"

    with (
        patch.object(auth, "usso_access_security", return_value=user),
        pytest.raises(PermissionDenied),
    ):
        view2(req)

    with (
        patch.object(auth, "usso_access_security", return_value=None),
        pytest.raises(USSOError),
    ):
        view(req)


def test_django_backend_and_middleware() -> None:
    """Backend authenticate/get_user and middleware process_request."""
    settings.USSO_JWT_CONFIG = _auth_config()
    backend = USSOAuthenticationBackend()
    assert backend.authenticate(None) is None

    req = MagicMock(spec=HttpRequest)
    user_data = UserData(sub="u1", phone="123", email="a@b.co")
    django_user = MagicMock()
    with (
        patch.object(
            USSOAuthentication,
            "usso_access_security",
            return_value=user_data,
        ),
        patch.object(backend, "get_or_create_user", return_value=django_user),
    ):
        assert backend.authenticate(req) is django_user

    with patch("usso.integrations.django.backend.User.objects") as objects:
        objects.filter.return_value.first.return_value = django_user
        assert backend.get_user(1) is django_user

    with patch("usso.integrations.django.backend.User.objects") as objects:
        objects.get_or_create.return_value = (django_user, True)
        created = backend.get_or_create_user(
            user_data=user_data,
            jwks_url="https://sso.example/.well-known/jwks.json",
        )
        assert created is django_user

    middleware = USSOAuthenticationMiddleware(get_response=lambda r: r)
    req2 = MagicMock(spec=HttpRequest)
    req2.user = MagicMock(is_authenticated=True)
    assert middleware.process_request(req2) is None

    req3 = MagicMock(spec=HttpRequest)
    # Ensure getattr(request, "user", None) is None
    type(req3).user = property(
        lambda _: (_ for _ in ()).throw(AttributeError())
    )
    with (
        patch.object(
            middleware,
            "jwt_access_security_none",
            return_value=user_data,
        ),
        patch.object(
            middleware, "get_or_create_user", return_value=django_user
        ),
    ):
        # Use a simple namespace without user attr
        req4 = MagicMock(spec=[])
        assert middleware.process_request(req4) is None

    req5 = MagicMock(spec=[])
    with patch.object(
        middleware,
        "jwt_access_security_none",
        side_effect=USSOError(401, "unauthorized", message="x"),
    ):
        resp = middleware.process_request(req5)
        assert resp is not None
        assert resp.status_code == 401

    assert middleware.jwt_config.jwks_url
    with patch.object(
        USSOAuthentication, "usso_access_security", return_value=None
    ):
        assert middleware.jwt_access_security_none(req5) is None
        assert middleware.jwt_access_security(req5) is None

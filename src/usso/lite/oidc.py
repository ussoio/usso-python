"""
Minimal OIDC helpers for USSO Lite identity login.

Paste/localhost-redirect flow: build an authorize URL, accept a pasted
callback (full URL / query / bare code), exchange the code, and read email
from userinfo (with optional unverified ``id_token`` payload fallback).

**Security note (v1 minimal):** when falling back to ``id_token``, the JWT
payload is base64-decoded only — Google JWKS signature verification is
intentionally skipped. Prefer ``userinfo`` email when available. Drive /
non-identity scopes are never requested from this module.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, NoReturn
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from ..exceptions import USSOException
from .config import OidcProviderConfig

__all__ = [
    "OidcParsedCallback",
    "OidcStateStore",
    "build_oidc_authorization_url",
    "decode_id_token_payload",
    "exchange_oidc_code",
    "fetch_oidc_userinfo",
    "parse_oidc_callback",
]

OIDC_STATE_TTL_SECONDS = 600


def _raise(status_code: int, error_code: str, en: str, fa: str) -> NoReturn:
    raise USSOException(
        status_code,
        error_code=error_code,
        message={"en": en, "fa": fa},
    )


@dataclass(frozen=True)
class _PendingState:
    provider: str
    created_at: float


@dataclass(frozen=True)
class OidcParsedCallback:
    """Result of parsing a pasted OIDC callback."""

    code: str | None = None
    state: str | None = None
    token: dict[str, Any] | None = None


class OidcStateStore:
    """In-memory CSRF state map with TTL (single-process only)."""

    def __init__(self, *, ttl_seconds: int = OIDC_STATE_TTL_SECONDS) -> None:
        """Initialize an empty state map with the given TTL."""
        self._ttl = ttl_seconds
        self._pending: dict[str, _PendingState] = {}

    def create(self, provider: str) -> str:
        """Create and store a new CSRF state for ``provider``."""
        self._purge_expired()
        state = secrets.token_urlsafe(32)
        self._pending[state] = _PendingState(
            provider=provider,
            created_at=time.monotonic(),
        )
        return state

    def consume(self, state: str, *, provider: str) -> bool:
        """Consume ``state`` once; return True if it matches ``provider``."""
        self._purge_expired()
        pending = self._pending.pop(state, None)
        if pending is None:
            return False
        return pending.provider == provider

    def _purge_expired(self) -> None:
        cutoff = time.monotonic() - self._ttl
        expired = [
            key
            for key, value in self._pending.items()
            if value.created_at < cutoff
        ]
        for key in expired:
            del self._pending[key]


def build_oidc_authorization_url(
    provider_config: OidcProviderConfig,
    state: str,
) -> str:
    """Build the provider authorize URL (openid/email/profile only)."""
    params = {
        "client_id": provider_config.client_id,
        "redirect_uri": provider_config.redirect_uri,
        "response_type": "code",
        "scope": " ".join(provider_config.scopes),
        "state": state,
    }
    return f"{provider_config.authorize_url}?{urlencode(params)}"


def parse_oidc_callback(raw: str) -> OidcParsedCallback:
    """Accept full URL, query string, bare code, or token JSON paste."""
    text = raw.strip()
    if not text:
        _raise(
            400,
            "oidc_callback_invalid",
            "OIDC callback paste is empty.",
            "مقدار بازگشتی OIDC خالی است.",
        )

    as_json = _try_parse_token_json(text)
    if as_json is not None:
        return OidcParsedCallback(token=as_json)

    if "://" in text or text.startswith("//"):
        return _parse_url(text)

    if "=" in text and (
        "code=" in text or "state=" in text or "access_token=" in text
    ):
        return _parse_query(text.lstrip("?#"))

    if all(ch not in text for ch in " \n\t{}[]"):
        return OidcParsedCallback(code=text)

    _raise(
        400,
        "oidc_callback_invalid",
        "Could not parse OIDC callback paste.",
        "مقدار بازگشتی OIDC قابل پردازش نیست.",
    )


def _try_parse_token_json(text: str) -> dict[str, Any] | None:
    if not (text.startswith("{") or text.startswith('"')):
        return None
    try:
        value: Any = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return None
    if isinstance(value, dict) and value.get("access_token"):
        return value
    return None


def _parse_url(url: str) -> OidcParsedCallback:
    parsed = urlparse(url)
    query = parsed.query or ""
    if not query and parsed.fragment:
        fragment = parsed.fragment
        if fragment.startswith("/"):
            frag_parsed = urlparse(
                fragment if "://" in fragment else f"x:{fragment}"
            )
            query = frag_parsed.query or fragment.lstrip("?#")
        else:
            query = fragment.lstrip("?")
    if not query:
        _raise(
            400,
            "oidc_callback_invalid",
            "Redirect URL has no OIDC parameters.",
            "آدرس بازگشت پارامتر OIDC ندارد.",
        )
    return _parse_query(query)


def _parse_query(query: str) -> OidcParsedCallback:
    params = parse_qs(query, keep_blank_values=False)
    flat = {key: values[0] for key, values in params.items() if values}

    if flat.get("access_token"):
        return OidcParsedCallback(token=dict(flat), state=flat.get("state"))

    error = flat.get("error") or flat.get("error_description")
    if error and not flat.get("code"):
        _raise(
            400,
            "oidc_callback_invalid",
            f"OIDC provider returned an error: {error}",
            f"ارائه‌دهنده OIDC خطا برگرداند: {error}",
        )

    code = flat.get("code")
    if not code:
        _raise(
            400,
            "oidc_callback_invalid",
            "Callback is missing an authorization code.",
            "کد مجوز در مقدار بازگشتی موجود نیست.",
        )
    return OidcParsedCallback(code=code, state=flat.get("state"))


def decode_id_token_payload(id_token: str) -> dict[str, Any]:
    """
    Decode the JWT payload segment of an ``id_token`` without signature check.

    Minimal identity login only — do not treat this as cryptographic proof
    of Google issuance. Prefer verified userinfo when available.
    """
    parts = id_token.split(".")
    if len(parts) < 2:
        _raise(
            400,
            "oidc_id_token_invalid",
            "id_token is malformed.",
            "id_token نامعتبر است.",
        )
    payload_b64 = parts[1]
    padding = "=" * (-len(payload_b64) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload_b64 + padding)
        data = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        _raise(
            400,
            "oidc_id_token_invalid",
            "id_token payload could not be decoded.",
            "بدنه id_token قابل رمزگشایی نیست.",
        )
    if not isinstance(data, dict):
        _raise(
            400,
            "oidc_id_token_invalid",
            "id_token payload must be a JSON object.",
            "بدنه id_token باید یک شیء JSON باشد.",
        )
    return data


async def exchange_oidc_code(
    provider_config: OidcProviderConfig,
    code: str,
    *,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Exchange an authorization code for tokens (access_token is enough)."""
    payload = {
        "code": code,
        "client_id": provider_config.client_id,
        "client_secret": provider_config.client_secret,
        "redirect_uri": provider_config.redirect_uri,
        "grant_type": "authorization_code",
    }

    async def _post(http: httpx.AsyncClient) -> httpx.Response:
        return await http.post(provider_config.token_url, data=payload)

    try:
        if client is None:
            async with httpx.AsyncClient(timeout=30.0) as http:
                response = await _post(http)
        else:
            response = await _post(client)
    except httpx.HTTPError as exc:
        _raise(
            502,
            "oidc_exchange_failed",
            f"Failed to reach OIDC token endpoint: {exc}",
            "ارتباط با نقطهٔ تبادل توکن OIDC ناموفق بود.",
        )

    if response.status_code >= 400:
        _raise(
            400,
            "oidc_exchange_failed",
            "OIDC token exchange failed.",
            "تبادل کد OIDC ناموفق بود.",
        )
    try:
        data = response.json()
    except ValueError:
        _raise(
            502,
            "oidc_exchange_failed",
            "OIDC token response was not JSON.",
            "پاسخ توکن OIDC معتبر نیست.",
        )
    if not isinstance(data, dict) or not data.get("access_token"):
        _raise(
            400,
            "oidc_exchange_failed",
            "OIDC token response missing access_token.",
            "پاسخ توکن OIDC فاقد access_token است.",
        )
    return data


async def fetch_oidc_userinfo(
    provider_config: OidcProviderConfig,
    access_token: str,
    *,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Fetch the OIDC userinfo document for ``access_token``."""

    async def _get(http: httpx.AsyncClient) -> httpx.Response:
        return await http.get(
            provider_config.userinfo_url,
            headers={"Authorization": f"Bearer {access_token}"},
        )

    try:
        if client is None:
            async with httpx.AsyncClient(timeout=30.0) as http:
                response = await _get(http)
        else:
            response = await _get(client)
    except httpx.HTTPError as exc:
        _raise(
            502,
            "oidc_userinfo_failed",
            f"Failed to reach OIDC userinfo endpoint: {exc}",
            "ارتباط با نقطهٔ userinfo ناموفق بود.",
        )

    if response.status_code >= 400:
        _raise(
            400,
            "oidc_userinfo_failed",
            "OIDC userinfo request failed.",
            "دریافت اطلاعات کاربر OIDC ناموفق بود.",
        )
    try:
        data = response.json()
    except ValueError:
        _raise(
            502,
            "oidc_userinfo_failed",
            "OIDC userinfo response was not JSON.",
            "پاسخ userinfo معتبر نیست.",
        )
    if not isinstance(data, dict):
        _raise(
            502,
            "oidc_userinfo_failed",
            "OIDC userinfo must be a JSON object.",
            "پاسخ userinfo باید یک شیء JSON باشد.",
        )
    return data

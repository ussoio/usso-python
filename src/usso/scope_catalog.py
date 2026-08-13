"""
Register microservice scopes into the USSO scope catalog.

Server-side catalog storage lives in the SSO service; this module is the
client helper every ICE service should call on startup.

Example::

    from usso.scope_catalog import register_scope_catalog, scopes_from_routers

    scopes = scopes_from_routers(
        [FilesRouter(), S3AccessKeyRouter()],
        actions=("read", "manage"),
    )
    await register_scope_catalog(service="media", scopes=scopes)
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

logger = logging.getLogger(__name__)

DEFAULT_ACTIONS: tuple[str, ...] = ("read", "manage")
DEFAULT_API_BASE_PATH = "/api/sso/v1"
DEFAULT_OAUTH_TOKEN_PATH = "/api/sso/v1/oauth/" + "token"
DEFAULT_HTTP_TIMEOUT = 15.0


def scopes_from_resource_paths(
    resource_paths: Iterable[str],
    *,
    actions: Sequence[str] = DEFAULT_ACTIONS,
    labels: Mapping[str, Mapping[str, str]] | None = None,
) -> list[dict[str, str]]:
    """
    Build catalog entries from USSO resource paths.

    Each path is typically ``namespace/service/resource`` as produced by
    ``AbstractUSSORouterBase.resource_path``.
    """
    labels = labels or {}
    entries: list[dict[str, str]] = []
    seen: set[str] = set()
    for path in resource_paths:
        resource_path = path.strip().strip("/")
        if not resource_path:
            continue
        for action in actions:
            scope = f"{action}:{resource_path}"
            if scope in seen:
                continue
            seen.add(scope)
            entry: dict[str, str] = {"scope": scope}
            meta = labels.get(scope) or labels.get(resource_path)
            if meta:
                entry.update({
                    key: value
                    for key, value in meta.items()
                    if key in {"label", "label_fa", "description"} and value
                })
            entries.append(entry)
    return entries


def scopes_from_routers(
    routers: Iterable[Any],
    *,
    actions: Sequence[str] = DEFAULT_ACTIONS,
    labels: Mapping[str, Mapping[str, str]] | None = None,
) -> list[dict[str, str]]:
    """
    Derive catalog scopes from USSO routers (duck-typed).

    Each router must expose ``resource_path`` (property or attribute), matching
    ``fastapi_mongo_base.utils.usso_routes.AbstractUSSORouterBase``.
    """
    paths: list[str] = []
    for router in routers:
        path = getattr(router, "resource_path", None)
        if callable(path):
            path = path()
        if path:
            paths.append(str(path))
    return scopes_from_resource_paths(paths, actions=actions, labels=labels)


async def fetch_client_credentials_token(
    *,
    usso_base_url: str,
    client_id: str,
    client_secret: str,
    oauth_token_path: str = DEFAULT_OAUTH_TOKEN_PATH,
    http_timeout: float = DEFAULT_HTTP_TIMEOUT,
) -> str:
    """Exchange OAuth client_credentials for an access token."""
    token_url = f"{usso_base_url.rstrip('/')}{oauth_token_path}"
    async with httpx.AsyncClient(timeout=http_timeout) as client:
        response = await client.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            },
        )
        response.raise_for_status()
        payload = response.json()
    token = payload.get("access_token")
    if not token:
        raise ValueError("Token response missing access_token")
    return token


async def put_scope_catalog(
    *,
    usso_base_url: str,
    service: str,
    scopes: Sequence[Mapping[str, str]],
    access_token: str,
    api_base_path: str = DEFAULT_API_BASE_PATH,
    http_timeout: float = DEFAULT_HTTP_TIMEOUT,
) -> None:
    """Replace service-sourced catalog entries for ``service``."""
    url = (
        f"{usso_base_url.rstrip('/')}"
        f"{api_base_path.rstrip('/')}/scope-catalog/{service}"
    )
    async with httpx.AsyncClient(timeout=http_timeout) as client:
        response = await client.put(
            url,
            headers={"Authorization": f"Bearer {access_token}"},
            json={"scopes": list(scopes)},
        )
        response.raise_for_status()


async def register_scope_catalog(
    *,
    service: str,
    scopes: Sequence[Mapping[str, str]],
    usso_base_url: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    api_base_path: str | None = None,
    oauth_token_path: str | None = None,
    enabled: bool | None = None,
    http_timeout: float = DEFAULT_HTTP_TIMEOUT,
) -> bool:
    """
    Best-effort startup registration of scopes into USSO.

    Credentials default to env vars:
    ``USSO_BASE_URL``, ``SCOPE_CATALOG_CLIENT_ID``,
    ``SCOPE_CATALOG_CLIENT_SECRET``.

    Returns True when a push was attempted and succeeded; False when skipped.
    Failures are logged and not raised (startup must not crash).
    """
    if enabled is None:
        enabled = os.getenv("SCOPE_CATALOG_ENABLED", "true").lower() in {
            "true",
            "1",
            "yes",
        }
    if not enabled:
        logger.info("Scope catalog registration disabled")
        return False

    usso_base_url = (
        usso_base_url or os.getenv("USSO_BASE_URL") or "https://sso.usso.io"
    )
    client_id = client_id or os.getenv("SCOPE_CATALOG_CLIENT_ID")
    client_secret = client_secret or os.getenv("SCOPE_CATALOG_CLIENT_SECRET")
    resolved_api_base_path = (
        api_base_path
        or os.getenv("USSO_API_BASE_PATH")
        or DEFAULT_API_BASE_PATH
    )
    resolved_oauth_token_path = (
        oauth_token_path
        or os.getenv("USSO_OAUTH_TOKEN_PATH")
        or DEFAULT_OAUTH_TOKEN_PATH
    )

    if not client_id or not client_secret:
        logger.info(
            "Skipping scope catalog registration "
            "(SCOPE_CATALOG_CLIENT_ID/SECRET unset)"
        )
        return False
    if not scopes:
        logger.info("Skipping scope catalog registration (empty scopes)")
        return False

    try:
        token = await fetch_client_credentials_token(
            usso_base_url=usso_base_url,
            client_id=client_id,
            client_secret=client_secret,
            oauth_token_path=resolved_oauth_token_path,
            http_timeout=http_timeout,
        )
        await put_scope_catalog(
            usso_base_url=usso_base_url,
            service=service,
            scopes=scopes,
            access_token=token,
            api_base_path=resolved_api_base_path,
            http_timeout=http_timeout,
        )
    except Exception:
        logger.exception(
            "Failed to register scopes for service=%s in USSO catalog",
            service,
        )
        return False
    else:
        logger.info(
            "Registered %s scopes for service=%s in USSO catalog",
            len(scopes),
            service,
        )
        return True

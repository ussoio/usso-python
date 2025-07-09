import fnmatch
import logging
from urllib.parse import parse_qs, urlparse

PRIVILEGE_LEVELS = {
    "read": 10,
    "create": 20,
    "update": 30,
    "delete": 40,
    "manage": 50,
    "owner": 90,
    "*": 90,
}


def parse_scope(scope: str) -> tuple[str, list[str], dict[str, str]]:
    """
    Parse a scope string into (action, path_parts, filters).

    Examples:
        "read:media/files/transaction?user_id=123" ->
            ("read", ["media", "files", "transaction"], {"user_id": "123"})

        "media/files/transaction?user_id=123" ->
            ("", ["media", "files", "transaction"], {"user_id": "123"})

        "*:*" ->
            ("*", ["*"], {})

    Returns:
        - action: str (could be empty string if no scheme present)
        - path_parts: list[str]
        - filters: dict[str, str]
    """

    parsed = urlparse(scope)
    path = parsed.path
    query = parsed.query
    filters = {k: v[0] for k, v in parse_qs(query).items()}
    path_parts = path.split("/") if path else ["*"]
    return parsed.scheme, path_parts, filters


def is_path_match(
    user_path: list[str] | str,
    requested_path: list[str] | str,
    strict: bool = False,
) -> bool:
    """
    Match resource paths from right to left, supporting wildcards (*).

    Rules:
    - The final resource name must match exactly or via fnmatch.
    - Upper-level path parts are matched from right to left.
    - Wildcards are allowed in any part.

    Examples = [
        ("files", "files", True),
        ("file-manager/files", "files", True),
        ("media/file-manager/files", "files", True),
        ("media//files", "files", True),
        ("media//files", "file-manager/files", True),
        ("files", "file-manager/files", True),
        ("*/files", "file-manager/files", True),
        ("*//files", "file-manager/files", True),
        ("//files", "file-manager/files", True),
        ("//files", "media/file-manager/files", True),
        ("media//files", "media/file-manager/files", True),
        ("media/files/*", "media/files/transactions", True),
        ("*/*/transactions", "media/files/transactions", True),
        ("media/*/transactions", "media/images/transactions", True),
        ("media//files", "media/files", True), # attention

        ("files", "file", False),
        ("files", "files/transactions", False),
        ("files", "media/files/transactions", False),
        ("media/files", "media/files/transactions", False),
    ]
    """
    if isinstance(user_path, str):
        user_parts = user_path.split("/")
    elif isinstance(user_path, list):
        user_parts = user_path
    else:
        raise ValueError(f"Invalid path type: {type(user_path)}")

    if isinstance(requested_path, str):
        req_parts = requested_path.split("/")
    elif isinstance(requested_path, list):
        req_parts = requested_path
    else:
        raise ValueError(f"Invalid path type: {type(requested_path)}")

    # Match resource name (rightmost)
    if not fnmatch.fnmatch(req_parts[-1], user_parts[-1]):
        return False

    # Match rest of the path from right to left
    user_path_parts = user_parts[:-1]
    req_path_parts = req_parts[:-1]

    for u, r in zip(
        reversed(user_path_parts),
        reversed(req_path_parts),
        strict=strict,
    ):
        if r and u and r != "*" and not fnmatch.fnmatch(r, u):
            return False

    return True


def is_filter_match(user_filters: dict, requested_filters: dict):
    """All user filters must match requested filters."""
    for k, v in user_filters.items():
        if k not in requested_filters or not fnmatch.fnmatch(
            str(requested_filters[k]), v
        ):
            return False
    return True


def is_authorized(
    user_scope: str,
    requested_path: str,
    requested_action: str | None = None,
    reuested_filter: dict[str, str] | None = None,
    *,
    strict: bool = False,
):
    user_action, user_path, user_filters = parse_scope(user_scope)

    if not is_path_match(user_path, requested_path, strict=strict):
        return False

    if not is_filter_match(user_filters, reuested_filter):
        return False

    if requested_action:
        user_level = PRIVILEGE_LEVELS.get(user_action or "read", 10)
        req_level = PRIVILEGE_LEVELS.get(requested_action, 0)
        return user_level >= req_level

    return True


def check_access(
    user_scopes: list[str],
    resource_path: str,
    action: str | None = None,
    *,
    filters: list[dict[str, str]] | dict[str, str] | None = None,
    strict: bool = False,
):
    """
    Check if the user has the required access to a resource.

    Args:
        user_scopes: list of user scope strings
        resource_path: resource path like "media/files/transactions"
        action: requested action like "read", "update", etc.
        filters: optional dict of filters like {"user_id": "abc"}

    Returns:
        True if access is granted, False otherwise
    """
    if isinstance(filters, dict):
        filters = [{k: v} for k, v in filters.items()]
    elif filters is None:
        filters = ["*"]

    for scope in user_scopes:
        for filter in filters:
            if is_authorized(
                user_scope=scope,
                requested_path=resource_path,
                requested_action=action,
                reuested_filter=filter,
                strict=strict,
            ):
                return True
            print(f"auth failed {filter}, {scope}")

    return False


def is_subset_scope(*, subset_scope: str, super_scope: str) -> bool:
    child_action, child_path, child_filters = parse_scope(subset_scope)
    parent_action, parent_path, parent_filters = parse_scope(super_scope)

    # 1. Compare privilege levels
    child_level = PRIVILEGE_LEVELS.get(child_action or "read", 10)
    parent_level = PRIVILEGE_LEVELS.get(parent_action or "read", 10)
    if parent_level < child_level:
        return False

    # 2. Compare path
    child_path_str = "/".join(child_path)
    parent_path_str = "/".join(parent_path)
    if not is_path_match(parent_path_str, child_path_str):
        return False

    # 3. Compare filters: parent_filters ⊆ child_filters
    for k, v in parent_filters.items():
        if child_filters.get(k) != v:
            return False

    logging.error(f"{parent_level}, {child_level}")

    return True


def has_subset_scope(*, subset_scope: str, user_scopes: list[str]) -> bool:
    for user_scope in user_scopes:
        if is_subset_scope(subset_scope=subset_scope, super_scope=user_scope):
            return True
    return False

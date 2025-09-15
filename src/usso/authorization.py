import fnmatch
from urllib.parse import parse_qs

PRIVILEGE_LEVELS = {
    "read": 10,
    "create": 20,
    "update": 30,
    "delete": 40,
    "manage": 50,
    "admin": 60,
    "owner": 90,
    "*": 90,
    "superadmin": 100,
}


def parse_scope(scope: str) -> tuple[str, list[str], dict[str, str]]:
    """Parse a scope string into (action, path_parts, filters).

    Examples:
        "read:media/files/transaction?user_id=123" ->
            ("read", ["media", "files", "transaction"], {"user_id": "123"})

        "media/files/transaction?user_id=123" ->
            ("", ["media", "files", "transaction"], {"user_id": "123"})

        "*:*" ->
            ("*", ["*"], {})

        "media//files" ->
            ("", ["media", "*", "files"], {})

    Returns:
        - action: str (could be empty string if no scheme present)
        - path_parts: list[str]
        - filters: dict[str, str]

    """
    colon_idx = scope.find(":")
    question_idx = scope.find("?")
    if question_idx == -1:
        question_idx = len(scope)

    if colon_idx != -1 and colon_idx < question_idx:
        action = scope[:colon_idx]
        resource_path = scope[colon_idx + 1 : question_idx]
    else:
        action = ""
        resource_path = scope[:question_idx]

    query = scope[question_idx + 1 :]
    filters = {k: v[0] for k, v in parse_qs(query).items()}
    resource_path_parts = resource_path.split("/") if resource_path else ["*"]
    return action, [rp or "*" for rp in resource_path_parts], filters


def _normalize_path(path: list[str] | str) -> list[str]:
    if isinstance(path, str):
        return path.split("/")
    elif isinstance(path, list):
        return path
    else:
        raise TypeError(f"Invalid path type: {type(path)}")


def _match_path_parts(
    user_parts: list[str], req_parts: list[str], strict: bool
) -> bool:
    wildcard_found = False
    # Match resource name (rightmost)
    if not fnmatch.fnmatch(req_parts[-1], user_parts[-1]):
        return False
    if "*" in user_parts[-1]:
        wildcard_found = True
    # Match rest of the path from right to left
    user_path_parts = user_parts[:-1]
    req_path_parts = req_parts[:-1]
    for u, r in zip(
        reversed(user_path_parts), reversed(req_path_parts), strict=strict
    ):
        if r and u and r != "*" and not fnmatch.fnmatch(r, u):
            return False
        if "*" in u:
            wildcard_found = True
    offset = len(user_path_parts) - len(req_path_parts)
    if offset > 0 and wildcard_found:
        for u in user_path_parts[:offset]:
            if u != "*":
                return False
    return True


def is_path_match(
    user_path: list[str] | str,
    requested_path: list[str] | str,
    strict: bool = False,
) -> bool:
    """Match resource paths from right to left, supporting wildcards (*)."""
    user_parts = _normalize_path(user_path)
    req_parts = _normalize_path(requested_path)
    return _match_path_parts(user_parts, req_parts, strict)


def is_filter_match(user_filters: dict, requested_filters: dict) -> bool:
    """All user filters must match requested filters."""
    for k, v in user_filters.items():
        if k not in requested_filters or not fnmatch.fnmatch(
            str(requested_filters[k]), v
        ):
            return False
    return True


def get_scope_filters(
    action: str,
    resource: str,
    user_scopes: list[str],
) -> list[dict]:
    """Return filters extracted from user scopes that:

    - Have equal or higher privilege level than the requested action.
    - Match the requested resource path.
    """
    matched_filters: list[dict] = []
    action_level = PRIVILEGE_LEVELS.get(action, 0)
    requested_parts = resource.split("/")

    for scope in user_scopes:
        scope_action, scope_path, scope_filters = parse_scope(scope)

        scope_level = PRIVILEGE_LEVELS.get(scope_action, 0)
        if scope_level < action_level:
            continue

        if not is_path_match(scope_path, requested_parts):
            continue

        matched_filters.append(scope_filters)

    return matched_filters


def broadest_scope_filter(filters: list[dict]) -> dict:
    """Return the broadest scope filter. It is used to select the most
    restrictive filter from the list of filters. by assigning a score
    to each filter based on the restriction bits. the filter with the
    lowest score is the most restrictive.

    filters = [
        {"tenant_id": "t1"},                           # score = 1
        {"workspace_id": "w1"},                        # score = 2
        {"user_id": "u1"},                             # score = 4
        {"uid": "abc"},                                # score = 8
        {"tenant_id": "t1", "user_id": "u1"},          # score = 1 + 4 = 5
        {"workspace_id": "w1", "uid": "abc"},          # score = 2 + 8 = 10
        {},                                            # score = 0
    ]
    """
    restriction_bits = {
        "tenant_id": 1 << 0,  # 1
        "workspace_id": 1 << 1,  # 2
        "user_id": 1 << 2,  # 4
        "uid": 1 << 3,  # 8
    }

    default_bit = 1 << 4

    if not filters:
        return {}

    def restriction_score(f: dict) -> int:
        if not f:
            return 0
        return sum(restriction_bits.get(k, default_bit) for k in f)

    return min(filters, key=restriction_score)


def owner_authorization(
    requested_filter: dict[str, str] | None = None,
    user_id: str | None = None,
    self_action: str = "owner",
    action: str = "read",
) -> bool:
    user_level = PRIVILEGE_LEVELS.get(self_action or "read", 10)
    req_level = PRIVILEGE_LEVELS.get(action or "read", 10)

    if (
        user_id
        and requested_filter
        and requested_filter.get("user_id") == user_id
    ):
        return user_level >= req_level
    return False


def is_authorized(
    user_scope: str,
    requested_path: str,
    requested_action: str = "read",
    requested_filter: dict[str, str] | None = None,
    *,
    strict: bool = False,
) -> bool:
    user_action, user_path, user_filters = parse_scope(user_scope)

    if not is_path_match(user_path, requested_path, strict=strict):
        return False

    if not is_filter_match(user_filters, requested_filter or {}):
        return False

    if requested_action:
        user_level = PRIVILEGE_LEVELS.get(user_action or "read", 10)
        req_level = PRIVILEGE_LEVELS.get(requested_action, 10)
        return user_level >= req_level

    return True


def check_access(
    user_scopes: list[str],
    resource_path: str,
    action: str | None = None,
    *,
    filters: list[dict[str, str]] | dict[str, str] | None = None,
    strict: bool = False,
) -> bool:
    """Check if the user has the required access to a resource.

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
        filters = [{}]

    for scope in user_scopes:
        for filt in filters:
            if is_authorized(
                user_scope=scope,
                requested_path=resource_path,
                requested_action=action,
                requested_filter=filt,
                strict=strict,
            ):
                return True

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
    return all(child_filters.get(k) == v for k, v in parent_filters.items())


def has_subset_scope(
    *, subset_scope: str, user_scopes: list[str] | str | None
) -> bool:
    user_scopes = user_scopes or []
    if isinstance(user_scopes, str):
        user_scopes = [user_scopes]
    for user_scope in user_scopes:
        if is_subset_scope(subset_scope=subset_scope, super_scope=user_scope):
            return True
    return False


def get_common_scopes(
    *, scopes_a: list[str], scopes_b: list[str]
) -> list[str]:
    """Update the scopes for the session."""

    not_permitted_scopes = [
        scope
        for scope in scopes_a
        if not has_subset_scope(subset_scope=scope, super_scope=scopes_b)
    ]
    if not not_permitted_scopes:
        return scopes_a

    new_permitted_scopes = [
        scope
        for scope in scopes_b
        if has_subset_scope(
            subset_scope=scope, super_scope=not_permitted_scopes
        )
    ]

    scopes_a = list(
        set(scopes_a + new_permitted_scopes) - set(not_permitted_scopes)
    )
    return scopes_a

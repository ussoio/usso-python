"""Coverage tests for the authorization module."""

from typing import Any, cast

import pytest

from usso import authorization
from usso.authorization import (
    _match_path_parts,
    _normalize_path,
    get_common_scopes,
    has_subset_scope,
    is_authorized,
    is_subset_scope,
)


def test_parse_path_invalid_type() -> None:
    """_normalize_path rejects non-string, non-list inputs."""
    with pytest.raises(TypeError):
        _normalize_path(cast(Any, 123))


def test_match_path_parts_mid_mismatch() -> None:
    """_match_path_parts rejects a mismatching path segment."""
    assert _match_path_parts(["a", "file"], ["b", "file"], False) is False


def test_is_authorized_without_action() -> None:
    """is_authorized returns True for a path match without an action."""
    assert is_authorized("read:files", "files", requested_action=None) is True


def test_is_subset_scope_path_mismatch() -> None:
    """is_subset_scope rejects scopes with different resource paths."""
    assert (
        is_subset_scope(subset_scope="read:a", super_scope="read:b") is False
    )


def test_has_subset_scope_string_input() -> None:
    """has_subset_scope accepts a single scope string."""
    assert (
        has_subset_scope(subset_scope="read:a", user_scopes="read:a") is True
    )


def test_get_common_scopes_all_permitted() -> None:
    """get_common_scopes keeps scopes_a when everything is permitted."""
    result = get_common_scopes(
        scopes_a=["read:a"], scopes_b=["read:a", "read:b"]
    )
    assert result == ["read:a"]


def test_get_common_scopes_filters_not_permitted() -> None:
    """get_common_scopes removes scopes not covered by scopes_b."""
    result = get_common_scopes(
        scopes_a=["read:a", "write:b"], scopes_b=["read:a"]
    )
    assert result == ["read:a"]


def test_get_common_scopes_adds_permitted_subset() -> None:
    """get_common_scopes adds permitted subset scopes back."""
    result = get_common_scopes(
        scopes_a=["read:a", "manage:c"], scopes_b=["read:a", "read:c"]
    )
    assert set(result) == {"read:a", "read:c"}


def test_get_scope_filters_matches() -> None:
    """get_scope_filters collects filters for matching scopes."""
    result = authorization.get_scope_filters(
        user_scopes=["read:users"], resource="users", action="read"
    )
    assert result == [{}]


def test_get_scope_filters_skips_low_privilege() -> None:
    """get_scope_filters skips scopes below the requested action level."""
    result = authorization.get_scope_filters(
        user_scopes=["read:users"], resource="users", action="manage"
    )
    assert result == []


def test_broadest_scope_filter_empty() -> None:
    """broadest_scope_filter returns an empty dict for no filters."""
    assert authorization.broadest_scope_filter([]) == {}


def test_broadest_scope_filter_restrictive() -> None:
    """broadest_scope_filter picks the lowest-scoring filter."""
    filters = [
        {"tenant_id": "t1"},
        {"tenant_id": "t1", "user_id": "u1"},
    ]
    assert authorization.broadest_scope_filter(filters) == {"tenant_id": "t1"}


def test_broadest_scope_filter_empty_and_custom() -> None:
    """broadest_scope_filter handles empty and unknown-key filters."""
    filters = [{}, {"custom": "x"}]
    assert authorization.broadest_scope_filter(filters) == {}

"""Tests for authorization and scope checking."""

import pytest

from src.usso.authorization import (
    check_access,
    has_subset_scope,
    is_authorized,
    is_path_match,
    is_subset_scope,
    owner_authorization,
)


@pytest.mark.parametrize(
    "requested_filter, user_id, self_action, action, expected",
    [
        ({"user_id": "123"}, "123", "owner", "read", True),
        ({}, "123", "owner", "create", False),
        ({"user_id": "123"}, "123", "read", "create", False),
    ],
)
def test_owner_authorization(
    requested_filter: dict[str, str],
    user_id: str,
    self_action: str,
    action: str,
    expected: bool,
) -> None:
    """Test owner authorization."""
    assert (
        owner_authorization(requested_filter, user_id, self_action, action)
        == expected
    )


def test_owner_authorization_workspace_id_defaults_to_self_action() -> None:
    """
    Test that omitting workspace_action leaves prior behavior unchanged.

    The match is granted at self_action level, same as an owner_id/
    user_id match.
    """
    assert owner_authorization(
        {"workspace_id": "w1"},
        self_action="owner",
        action="delete",
        workspace_id="w1",
    )


@pytest.mark.parametrize(
    "requested_filter, workspace_id, action, workspace_action, expected",
    [
        # workspace_action caps a workspace-only match to read.
        ({"workspace_id": "w1"}, "w1", "read", "read", True),
        ({"workspace_id": "w1"}, "w1", "update", "read", False),
        # Raising workspace_action explicitly allows more.
        ({"workspace_id": "w1"}, "w1", "update", "update", True),
        # Different workspace -> no grant.
        ({"workspace_id": "w2"}, "w1", "read", "read", False),
        # No workspace_id on the caller -> no grant.
        ({"workspace_id": "w1"}, None, "read", "read", False),
        # No workspace_id on the resource -> no grant.
        ({}, "w1", "read", "read", False),
    ],
)
def test_owner_authorization_workspace_action_cap(
    requested_filter: dict[str, str],
    workspace_id: str | None,
    action: str,
    workspace_action: str,
    expected: bool,
) -> None:
    """
    Test that workspace_action caps a workspace-only match.

    When explicitly given, it caps the privilege level granted via a
    workspace-only match (no owner_id/user_id match) -- e.g. a workspace
    member gets read access to the workspace's shared resources without
    automatic edit/delete rights over resources created by other members.
    """
    assert (
        owner_authorization(
            requested_filter,
            action=action,
            workspace_id=workspace_id,
            workspace_action=workspace_action,
        )
        == expected
    )


def test_owner_match_ignores_workspace_action_cap() -> None:
    """
    Test that an owner match is not capped by workspace_action.

    When the match came through owner_id/user_id (not just workspace_id),
    workspace_action's cap doesn't apply -- the owner still gets full
    self_action-level rights over their own resource, even if it's also
    tagged with a workspace_id.
    """
    assert owner_authorization(
        {"user_id": "u1", "workspace_id": "w1"},
        user_id="u1",
        self_action="owner",
        action="delete",
        workspace_id="w1",
        workspace_action="read",
    )


@pytest.mark.parametrize(
    "user_scope,requested_path,requested_action,requested_filter,strict,expected",
    [
        (
            "read:media/files",
            "media/files",
            "read",
            {"user_id": "123"},
            False,
            True,
        ),
        ("read:media/files", "media/files", "read", None, False, True),
        ("media/files", "media/files", "read", None, False, True),
        ("media/files", "files", "create", None, False, False),
        ("media/*", "files", "read", None, False, False),
        ("read:media/files", "media/files", "create", None, False, False),
    ],
)
def test_is_authorized(
    user_scope: str,
    requested_path: str,
    requested_action: str,
    requested_filter: dict[str, str] | None,
    strict: bool,
    expected: bool,
) -> None:
    """Test is authorized."""
    assert (
        is_authorized(
            user_scope,
            requested_path,
            requested_action,
            requested_filter,
            strict=strict,
        )
        == expected
    )


@pytest.mark.parametrize(
    "user_path, requested_path, expected",
    [
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
        ("files", "file", False),
        ("files", "files/transactions", False),
        ("files", "media/files/transactions", False),
        ("media/files", "media/files/transactions", False),
        ("finance/*/*", "wallet", False),
        ("media//files", "media/files", True),
    ],
)
def test_path_match(
    user_path: str, requested_path: str, expected: bool
) -> None:
    """Test path match."""
    assert is_path_match(user_path, requested_path, strict=False) == expected


# Define pytest tests
def test_exact_match_id() -> None:
    """Test exact match id."""
    scopes = ["read:media/file-manager/files?uid=file123"]
    assert (
        check_access(
            scopes,
            "files",
            action="read",
            filters=[
                {"namespace": "media"},
                {"service": "file-manager"},
                {"uid": "file123"},
            ],
        )
        is True
    )


# Define pytest tests
def test_wildcard() -> None:
    """Test wildcard."""
    scopes = [
        "update:media/files/transactions?user_id=abc",
        "read:media/files/*",
    ]

    assert check_access(
        scopes,
        "media/files/transactions",
        action="read",
        filters={"user_id": "abc"},
    )
    assert check_access(
        scopes, "transactions", action="update", filters={"user_id": "abc"}
    )
    assert not check_access(
        scopes, "transactions", action="update", filters={"uid": "def"}
    )
    assert not check_access(
        scopes,
        "media/files/transactions",
        action="delete",
        filters={"user_id": "abc"},
    )


def test_insufficient_privilege() -> None:
    """Test insufficient privilege."""
    scopes = ["read:media/files/file:uid:file123"]
    assert (
        check_access(
            scopes,
            "file",
            "update",
            filters=[
                {"namespace": "finance"},
                {"service": "wallet"},
                {"workspace_id": "ws_7"},
            ],
        )
        is False
    )


def test_wildcard_match() -> None:
    """Test wildcard match."""
    scopes = ["manage:media/files/file?*"]
    assert (
        check_access(
            scopes,
            "file",
            "update",
            filters={
                "namespace": "finance",
                "service": "wallet",
                "workspace_id": "ws_7",
            },
        )
        is True
    )


def test_match_by_user_id() -> None:
    """Test match by user id."""
    scopes = ["manage:finance/wallet/transaction?user=user_1"]
    assert (
        check_access(
            scopes,
            "transaction",
            "update",
            filters=[
                {"namespace": "finance"},
                {"service": "wallet"},
                {"workspace_id": "ws_7"},
            ],
        )
        is False
    )
    assert (
        check_access(
            scopes,
            "transaction",
            "update",
            filters={"namespace": "finance", "user": "user_1"},
        )
        is True
    )


def test_match_by_workspace_id() -> None:
    """Test match by workspace id."""
    scopes = ["delete:finance/wallet/transaction?workspace_id=ws_7"]
    assert (
        check_access(
            scopes,
            "transaction",
            "delete",
            filters=[
                {"namespace": "finance"},
                {"service": "wallet"},
                {"workspace_id": "ws_7"},
            ],
        )
        is True
    )


def test_minimal_params_success() -> None:
    """Test minimal params success."""
    scopes = ["create:file?*"]
    assert check_access(scopes, "file", "create") is True


def test_minimal_params_fail() -> None:
    """Test minimal params fail."""
    scopes = ["read:file?*"]
    assert check_access(scopes, "file", "create") is False


def test_minimal_params_read_create_fail() -> None:
    """Test minimal params read create fail."""
    scopes = ["file"]
    assert check_access(scopes, "file", "create") is False


def test_scope_subset() -> None:
    """Test scope subset."""
    assert is_subset_scope(
        subset_scope="read:media/files?user_id=123",
        super_scope="read:media/files",
    )
    assert is_subset_scope(
        subset_scope="read:media/files?user_id=123", super_scope="read:media/*"
    )
    assert not is_subset_scope(
        subset_scope="create:media/files", super_scope="read:media/files"
    )
    assert not is_subset_scope(
        subset_scope="update:media/files", super_scope="read:media/files"
    )
    assert not is_subset_scope(
        subset_scope="read:media/files?user_id=123",
        super_scope="read:media/files?user_id=456",
    )
    assert not is_subset_scope(
        subset_scope="read:media/files?user_id=123",
        super_scope="read:media/files?workspace_id=123",
    )
    assert is_subset_scope(subset_scope="read:files", super_scope="read:*")
    assert is_subset_scope(
        subset_scope="read:files", super_scope="read://files"
    )

    assert has_subset_scope(
        subset_scope="files", user_scopes=["read:files", "create:files"]
    )
    assert not is_subset_scope(
        subset_scope="create:files", super_scope="files"
    )
    assert not is_subset_scope(subset_scope="create:files", super_scope="*")
    assert is_subset_scope(subset_scope="create:files", super_scope="*:*")
    assert is_subset_scope(
        subset_scope="create:files", super_scope="*://files"
    )

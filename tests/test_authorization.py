import pytest

from src.usso.auth.authorization import (
    check_access,
    has_subset_scope,
    is_path_match,
    is_subset_scope,
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
        (
            "media//files",
            "media/files",
            True,
        ),  # !! atention it matches because the middle part is empty
        ("media/files/*", "media/files/transactions", True),
        ("*/*/transactions", "media/files/transactions", True),
        ("media/*/transactions", "media/images/transactions", True),
        ("files", "file", False),
        ("files", "files/transactions", False),
        ("files", "media/files/transactions", False),
        ("media/files", "media/files/transactions", False),
    ],
)
def test_path_match(user_path, requested_path, expected):
    assert is_path_match(user_path, requested_path, strict=False) == expected


# Define pytest tests
def test_exact_match_id():
    scopes = ["read:media/file-manager/files?uid=file123"]
    assert (
        check_access(
            scopes,
            "files",
            action="read",
            filters=[
                dict(namespace="media"),
                dict(service="file-manager"),
                dict(uid="file123"),
            ],
        )
        is True
    )


# Define pytest tests
def test_wildcard():
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


def test_insufficient_privilege():
    scopes = ["read:media/files/file:uid:file123"]
    assert (
        check_access(
            scopes,
            "file",
            "update",
            filters=[
                dict(namespace="finance"),
                dict(service="wallet"),
                dict(workspace_id="ws_7"),
            ],
        )
        is False
    )


def test_wildcard_match():
    scopes = ["manage:media/files/file?*"]
    assert (
        check_access(
            scopes,
            "file",
            "update",
            filters=dict(
                namespace="finance",
                service="wallet",
                workspace_id="ws_7",
            ),
        )
        is True
    )


def test_match_by_user_id():
    scopes = ["manage:finance/wallet/transaction?user=user_1"]
    assert (
        check_access(
            scopes,
            "transaction",
            "update",
            filters=[
                dict(namespace="finance"),
                dict(service="wallet"),
                dict(workspace_id="ws_7"),
            ],
        )
        is False
    )
    assert (
        check_access(
            scopes,
            "transaction",
            "update",
            filters=dict(namespace="finance", user="user_1"),
        )
        is True
    )


def test_match_by_workspace_id():
    scopes = ["delete:finance/wallet/transaction?workspace_id=ws_7"]
    assert (
        check_access(
            scopes,
            "transaction",
            "delete",
            filters=[
                dict(namespace="finance"),
                dict(service="wallet"),
                dict(workspace_id="ws_7"),
            ],
        )
        is True
    )


def test_minimal_params_success():
    scopes = ["create:file?*"]
    assert check_access(scopes, "file", "create") is True


def test_minimal_params_fail():
    scopes = ["read:file?*"]
    assert check_access(scopes, "file", "create") is False


def test_minimal_params_read_create_fail():
    scopes = ["file"]
    assert check_access(scopes, "file", "create") is False


def test_scope_subset():
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

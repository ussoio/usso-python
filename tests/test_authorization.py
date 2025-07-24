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
    assert (
        owner_authorization(requested_filter, user_id, self_action, action)
        == expected
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
    assert is_path_match(user_path, requested_path, strict=False) == expected


# Define pytest tests
def test_exact_match_id() -> None:
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
    scopes = ["create:file?*"]
    assert check_access(scopes, "file", "create") is True


def test_minimal_params_fail() -> None:
    scopes = ["read:file?*"]
    assert check_access(scopes, "file", "create") is False


def test_minimal_params_read_create_fail() -> None:
    scopes = ["file"]
    assert check_access(scopes, "file", "create") is False


def test_scope_subset() -> None:
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

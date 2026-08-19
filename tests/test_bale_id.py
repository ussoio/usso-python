"""Tests for the Bale messenger identifier type."""

from datetime import UTC, datetime

from src.usso.enums import AuthIdentifier
from src.usso.schemas import UserResponse


def test_bale_id_enum_value() -> None:
    """Bale IDs are a first-class identifier type, not a telegram_id alias."""
    assert AuthIdentifier.BALE_ID.value == "bale_id"
    is_valid, error, canonical = AuthIdentifier.BALE_ID.get_identifier_validator()(
        "712091689"
    )
    assert is_valid is True
    assert error is None
    assert canonical == "712091689"


def test_user_response_accepts_bale_id_identifier() -> None:
    """
    Regression for AITOOLKIT-2.

    USSO returns ``bale_id`` on users who also have telegram_id. The
    client must parse that response instead of raising ValidationError
    and breaking every lookup for that user.
    """
    now = datetime(2026, 1, 1, tzinfo=UTC)
    user = UserResponse.model_validate(
        {
            "uid": "0197f464-46e0-7392-a54f-b08f07be6926",
            "created_at": now,
            "updated_at": now,
            "is_deleted": False,
            "tenant_id": "0197f464-46c8-72a1-8b23-0819b8622a0c",
            "roles": [],
            "identifiers": [
                {
                    "uid": "019ffc92-17ce-796e-911a-7c0b5e22d5bd",
                    "created_at": now,
                    "updated_at": now,
                    "is_deleted": False,
                    "tenant_id": "0197f464-46c8-72a1-8b23-0819b8622a0c",
                    "type": "bale_id",
                    "identifier": "712091689",
                }
            ],
        }
    )
    assert user.identifiers[0].type == AuthIdentifier.BALE_ID
    assert user.identifiers[0].identifier == "712091689"

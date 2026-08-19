"""
SQLAlchemy base entity classes for USSO Lite.

These mirror the ``fastapi_mongo_base.sql.models`` pattern so that models
stay conceptually compatible with the full USSO platform. Since USSO Lite
is single-tenant, no ``tenant_id`` column is included.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, MetaData, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

__all__ = ["Base", "BaseEntity", "UserEntity"]

naming_convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative base for all USSO Lite models."""

    metadata = MetaData(naming_convention=naming_convention)


def _utcnow() -> datetime:
    """Return a naive UTC timestamp (like fastapi-mongo-base SQL base)."""
    return datetime.now(UTC).replace(tzinfo=None)


def _uuid4() -> str:
    """Return a string UUID4, matching the SQL base in fastapi-mongo-base."""
    return str(uuid.uuid4())


class BaseEntity:
    """Base entity with common fields and helpers."""

    __abstract__ = True

    uid: Mapped[str] = mapped_column(
        primary_key=True,
        default=_uuid4,
        unique=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=_utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=_utcnow, onupdate=func.now()
    )
    is_deleted: Mapped[bool] = mapped_column(default=False)
    meta_data: Mapped[dict[str, Any] | None] = mapped_column(
        JSON, nullable=True
    )

    def dump(
        self,
        include_fields: list[str] | None = None,
        exclude_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Dump the entity into a plain dictionary.

        Args:
            include_fields: Fields to include (all by default).
            exclude_fields: Fields to exclude.

        Returns:
            A dictionary representation of the entity.
        """
        result: dict[str, Any] = {}
        for key in include_fields or self.__dict__.keys():
            if key.startswith("_"):
                continue
            if not hasattr(self, key):
                continue
            if exclude_fields and key in exclude_fields:
                continue
            value = getattr(self, key)
            if isinstance(value, datetime):
                result[key] = value.isoformat()
            else:
                result[key] = value
        return result

    def __repr__(self) -> str:
        """Human-readable representation."""
        return f"<{self.__class__.__name__} uid={self.uid}>"

    def __hash__(self) -> int:
        """Hash based on the dumped representation."""
        return hash(json.dumps(self.dump(), sort_keys=True, default=str))


class UserEntity(BaseEntity):
    """Base entity scoped to a user."""

    __abstract__ = True

    user_id: Mapped[str | None] = mapped_column(
        ForeignKey("localuser.uid"),
        nullable=True,
        index=True,
    )

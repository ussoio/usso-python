"""Dependency-free identifier validation for USSO Lite."""

from __future__ import annotations

import re

from ..enums import AuthIdentifier

_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}$"
)
_USERNAME_RE = re.compile(
    r"^(?=.{3,30}$)[A-Za-z0-9_](?:[A-Za-z0-9]|[._-](?=[A-Za-z0-9]))*$"
)
_PHONE_RE = re.compile(r"^\+?[0-9]{7,15}$")
_RESERVED_USERNAMES = frozenset({
    "admin",
    "administrator",
    "api",
    "root",
    "support",
    "system",
})


def validate_email(email: str) -> tuple[bool, str, str]:
    """Validate and normalize an email without network access."""
    value = email.strip().lower()
    if len(value) > 254 or not _EMAIL_RE.fullmatch(value):
        return False, "Email is invalid", ""
    local, domain = value.rsplit("@", 1)
    if len(local) > 64 or ".." in local or ".." in domain:
        return False, "Email is invalid", ""
    return True, "", value


def validate_phone(number: str) -> tuple[bool, str, str]:
    """Validate and normalize a lightweight international phone number."""
    value = re.sub(r"[\s().-]", "", number.strip())
    if not _PHONE_RE.fullmatch(value):
        return False, "Invalid phone number", ""
    return True, "", value


def validate_username(username: str) -> tuple[bool, str, str]:
    """Validate and normalize a username."""
    value = username.strip().lower()
    if not _USERNAME_RE.fullmatch(value):
        return False, "Username is invalid", ""
    if value in _RESERVED_USERNAMES:
        return False, "This username is reserved", ""
    return True, "", value


def canonicalize_identifier(type_: AuthIdentifier, value: str) -> str:
    """Validate and canonicalize a supported identifier."""
    validator = {
        AuthIdentifier.EMAIL: validate_email,
        AuthIdentifier.PHONE: validate_phone,
        AuthIdentifier.USERNAME: validate_username,
    }.get(type_)
    if validator is None:
        raise ValueError("USSO Lite supports email, phone and username only.")
    valid, error, canonical = validator(value)
    if not valid:
        raise ValueError(error)
    return canonical


def infer_identifier_type(value: str) -> AuthIdentifier:
    """Infer and validate an email, phone or username identifier."""
    for validator, identifier_type in (
        (validate_email, AuthIdentifier.EMAIL),
        (validate_phone, AuthIdentifier.PHONE),
        (validate_username, AuthIdentifier.USERNAME),
    ):
        if validator(value)[0]:
            return identifier_type
    raise ValueError(
        "Identifier must be a valid email, phone number or username."
    )

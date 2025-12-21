"""Validation utilities for identifiers and credentials."""

import logging
import re
import string
import unicodedata
from collections.abc import Iterable
from enum import Enum

username_regex = (
    r"^(?=.{3,30}$)[A-Za-z0-9_](?:[A-Za-z0-9]|[._-](?=[A-Za-z0-9]))*$"
)
email_regex = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
international_phone_regex = re.compile(
    r"^[\+]?(0{0,2})(9[976]\d|8[987530]\d|6[987]\d|5[90]\d|42\d|3[875]\d|2[98654321]\d|9[8543210]|8[6421]|6[6543210]|5[87654321]|4[987654310]|3[9643210]|2[70]|7|1)\W*\d\W*\d\W*\d\W*\d\W*\d\W*\d\W*\d\W*\d\W*(\d{1,2})$"
)
telegram_id_regex = re.compile(r"^\d{5,15}+$")


def convert_to_english_digits(input_str: str) -> str:
    """
    Convert Unicode digits to ASCII digits.

    Args:
        input_str: String that may contain Unicode digits.

    Returns:
        str: String with all digits converted to ASCII (0-9).

    """
    result = []
    for char in input_str:
        if char.isdigit():
            # Convert any unicode digit to its corresponding ASCII digit
            result.append(unicodedata.digit(char))
        else:
            result.append(char)
    return "".join(map(str, result))


def validate_phone(
    number: str, country_code: str | None = None
) -> tuple[bool, str, str]:
    """
    Validate a phone number.

    Args:
        number: Phone number string to validate.
        country_code: Optional country code for validation.

    Returns:
        tuple[bool, str, str]: (is_valid, error_message, canonical_number).
            error_message is None if valid.

    """
    import phonenumbers

    try:
        parsed = phonenumbers.parse(number, country_code)
        if (
            country_code
            and phonenumbers.country_code_for_region(country_code)
            != parsed.country_code
        ):
            return False, "Invalid country code", None

        if not phonenumbers.is_valid_number(parsed):
            return False, "Invalid phone number", None
    except phonenumbers.NumberParseException as e:
        return False, str(e), None

    return True, None, f"{parsed.country_code}{parsed.national_number}"


def validate_telegram_id(inp: str) -> tuple[bool, str, str]:
    """
    Validate a Telegram user ID.

    Args:
        inp: String to validate as Telegram ID.

    Returns:
        tuple[bool, str, str]: (is_valid, error_message, canonical_id).
            error_message is None if valid.

    """
    if telegram_id_regex.search(inp):
        return True, None, inp
    return False, "Invalid Telegram ID", None


def validate_email(email: str) -> tuple[bool, str, str]:
    """
    Validate an email address.

    Args:
        email: Email address string to validate.

    Returns:
        tuple[bool, str, str]: (is_valid, error_message, canonical_email).
            error_message is None if valid.

    """
    import dns.resolver
    import email_validator

    try:
        # First try with DNS validation but catch only
        # timeout/connection errors
        try:
            resolver = email_validator.caching_resolver(
                timeout=5
            )  # Reduced timeout
            mail_address = email_validator.validate_email(
                email, dns_resolver=resolver, check_deliverability=True
            )
        except dns.resolver.NoResolverConfiguration:
            logging.warning("no dns")
            mail_address = email_validator.validate_email(
                email, check_deliverability=False
            )
    except email_validator.EmailNotValidError:
        return False, "Email is invalid", None

    if mail_address.domain != "gmail.com":
        return True, None, mail_address.normalized

    email_user = mail_address.ascii_local_part.split("+")[0].replace(".", "")
    return True, None, f"{email_user}@gmail.com"


separators = "._-"

reserved = {
    "admin",
    "administrator",
    "root",
    "system",
    "support",
    "help",
    "about",
    "api",
    "v1",
    "login",
    "logout",
    "signup",
    "register",
    "me",
    "null",
    "nil",
    "undefined",
    "postmaster",
    "abuse",
}
banned_words = {
    # keep lowercase
    "shit",
    "fuck",
    "bitch",
    "asshole",
    "bastard",
    "nazi",
    "hitler",
    "rape",
    "rapist",
    "cum",
    "cunt",
    "dick",
    "faggot",
    "whore",
    "sex",
    "sexy",
    "vagina",
    "pussy",
    "porn",
    "nude",
}


def _to_ascii_nfkc_lower(s: str) -> str:
    """
    Normalize to NFKC, enforce ASCII, then lowercase.

    Raises ValueError if non-ASCII survives normalization.
    """
    s = unicodedata.normalize("NFKC", s).strip()
    try:
        s.encode("ascii", "strict")
    except UnicodeEncodeError as e:
        raise ValueError("Only ASCII usernames are allowed.") from e
    return s.lower()


def _canonical_for_reserved(s_lower_ascii: str) -> str:
    """
    Canonicalize for reserved-name matching.

    - strip leading/trailing separators
    - collapse any run of separators to a single underscore.
    """
    # strip leading/trailing separators
    t = s_lower_ascii.strip(separators)
    # collapse runs of separators into single underscore
    out = []
    prev_sep = False
    for ch in t:
        if ch in separators:
            if not prev_sep:
                out.append(ch)
            prev_sep = True
        else:
            out.append(ch)
            prev_sep = False
    return "".join(out)


def _alnum_only(s_lower_ascii: str) -> str:
    """Remove separators; keep only a-z and 0-9."""
    return "".join(
        ch
        for ch in s_lower_ascii
        if ch in string.ascii_letters + string.digits
    )


def _contains_bad_word(
    s_lower_ascii: str, bad_words: Iterable[str]
) -> tuple[bool, str]:
    """
    Check for bad words.

    Checks substring after removing separators
    (blocks 'b.a.d' evasion).
    """
    compact = _alnum_only(s_lower_ascii)
    for word in bad_words:
        if not word:  # defensive
            continue
        if word in compact:
            return True, word
    return False, ""


def validate_username(
    username: str,
    reserved: Iterable[str] = reserved,
    bad_words: Iterable[str] = banned_words,
) -> tuple[bool, str, str]:
    """
    Validate a username.

    Returns:
        (is_valid, message, canonical_username)

    canonical_username is the lowercase form suitable for uniqueness
    checks/storage (after NFKC + ASCII enforcement).

    """
    # 1) Normalize & ASCII-enforce & lowercase
    try:
        uname = _to_ascii_nfkc_lower(username)
    except ValueError as e:
        return False, str(e), None

    # 2) Regex policy
    if not re.match(username_regex, uname):
        return (
            False,
            (
                "Username must be 3-30 chars, ASCII, start with a letter "
                "or underscore, contain letters/digits/._- nothing else, "
                "and must not end with or repeat separators."
            ),
            None,
        )

    # 3) Reserved names (case-insensitive, canonicalized)
    reserved_norm = {_canonical_for_reserved(r.lower()) for r in reserved}
    uname_reserved_key = _canonical_for_reserved(uname)
    if uname_reserved_key in reserved_norm:
        return False, "This username conflicts with a reserved name.", None

    # 4) Bad words (case-insensitive; detect through separators)
    is_bad, bad_word = _contains_bad_word(
        uname, {w.lower() for w in bad_words}
    )
    if is_bad:
        return (
            False,
            f"Username contains disallowed language: {bad_word}",
            None,
        )

    # 5) Success
    return True, None, uname


def determine_identifier_type(payload: dict) -> tuple[Enum, str]:
    """
    Determine the identifier type and value from a payload.

    Checks for phone, email, or username in the payload, or attempts
    to validate the 'sub' field as one of these types.

    Args:
        payload: Dictionary containing identifier information.

    Returns:
        tuple[Enum, str]: Tuple of (AuthIdentifier enum, canonical_value).
            Returns (None, None) if no valid identifier is found.

    """
    from ..enums import AuthIdentifier

    if payload.get("phone"):
        return AuthIdentifier.PHONE, payload.get("phone")
    elif payload.get("email"):
        return AuthIdentifier.EMAIL, payload.get("email")
    elif payload.get("username"):
        return AuthIdentifier.USERNAME, payload.get("username")

    sub = payload.get("sub")
    valid, _, canonical_sub = validate_email(sub)
    if valid:
        return AuthIdentifier.EMAIL, canonical_sub
    valid, _, canonical_sub = validate_phone(sub)
    if valid:
        return AuthIdentifier.PHONE, canonical_sub
    valid, _, canonical_sub = validate_username(sub)
    if valid:
        return AuthIdentifier.USERNAME, canonical_sub
    return None, None

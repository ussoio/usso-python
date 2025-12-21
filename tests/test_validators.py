"""Test validators."""

from src.usso.enums import AuthIdentifier
from src.usso.utils.validators import (
    convert_to_english_digits,
    determine_identifier_type,
    validate_email,
    validate_phone,
    validate_telegram_id,
    validate_username,
)


class TestConvertToEnglishDigits:
    """Test convert_to_english_digits function."""

    def test_ascii_digits_unchanged(self) -> None:
        """Test that ASCII digits remain unchanged."""
        assert convert_to_english_digits("123") == "123"
        assert convert_to_english_digits("abc123def") == "abc123def"

    def test_unicode_digits_converted(self) -> None:
        """Test that Unicode digits are converted to ASCII."""
        # Persian/Arabic digits
        persian_digits = "۱۲۳"
        assert convert_to_english_digits(persian_digits) == "123"
        # Bengali digits
        bengali_digits = "১২৩"
        assert convert_to_english_digits(bengali_digits) == "123"
        # Mixed
        mixed = f"abc{persian_digits}-{bengali_digits}def"
        assert convert_to_english_digits(mixed) == "abc123-123def"

    def test_non_digit_characters_unchanged(self) -> None:
        """Test that non-digit characters remain unchanged."""
        assert convert_to_english_digits("hello") == "hello"
        assert convert_to_english_digits("!@#$%") == "!@#$%"

    def test_empty_string(self) -> None:
        """Test empty string."""
        assert convert_to_english_digits("") == ""


class TestDetermineIdentifierType:
    """Test determine_identifier_type function."""

    def test_determine_identifier_type_phone(self) -> None:
        """Test determine_identifier_type function with phone."""
        identifier_type, value = determine_identifier_type({
            "phone": "+1234567890"
        })
        assert identifier_type == AuthIdentifier.PHONE
        assert value == "+1234567890"

    def test_determine_identifier_type_email(self) -> None:
        """Test determine_identifier_type function with email."""
        identifier_type, value = determine_identifier_type({
            "email": "user@example.com"
        })
        assert identifier_type == AuthIdentifier.EMAIL
        assert value == "user@example.com"

    def test_determine_identifier_type_username(self) -> None:
        """Test determine_identifier_type function with username."""
        identifier_type, value = determine_identifier_type({
            "username": "john_doe"
        })
        assert identifier_type == AuthIdentifier.USERNAME
        assert value == "john_doe"

    def test_determine_identifier_type_sub_username(self) -> None:
        """Test determine_identifier_type function with username."""
        identifier_type, value = determine_identifier_type({"sub": "john_doe"})
        assert identifier_type == AuthIdentifier.USERNAME
        assert value == "john_doe"

    def test_determine_identifier_type_sub_phone(self) -> None:
        """Test determine_identifier_type function with phone."""
        identifier_type, value = determine_identifier_type({
            "sub": "+1 (415) 555-0173"
        })
        assert identifier_type == AuthIdentifier.PHONE
        assert value == "14155550173"

    def test_determine_identifier_type_sub_email(self) -> None:
        """Test determine_identifier_type function with email."""
        identifier_type, value = determine_identifier_type({
            "sub": "user@usso.io"
        })
        assert identifier_type == AuthIdentifier.EMAIL
        assert value == "user@usso.io"

    def test_determine_identifier_invalid(self) -> None:
        """Test determine_identifier_type function with email."""
        identifier_type, value = determine_identifier_type({
            "sub": "user@example.com"
        })
        assert identifier_type is None
        assert value is None


class TestValidators:
    """Test validators."""

    def test_validate_email(self) -> None:
        """Test validate_email function."""
        is_valid, error, canonical = validate_email("user@usso.io")
        assert is_valid is True
        assert error is None
        assert canonical == "user@usso.io"

    def test_validate_gmail(self) -> None:
        """Test validate_email function."""
        is_valid, error, canonical = validate_email("user@gmail.com")
        assert is_valid is True
        assert error is None
        assert canonical == "user@gmail.com"

    def test_validate_phone(self) -> None:
        """Test validate_phone function."""
        is_valid, error, canonical = validate_phone("+1 (415) 555-0173")
        assert error is None
        assert is_valid is True
        assert canonical == "14155550173"

    def test_validate_username(self) -> None:
        """Test validate_username function."""
        is_valid, error, canonical = validate_username("john_doe")
        assert is_valid is True
        assert error is None
        assert canonical == "john_doe"

    def test_validate_telegram_id(self) -> None:
        """Test validate_telegram_id function."""
        is_valid, error, canonical = validate_telegram_id("123456789")
        assert error is None
        assert is_valid is True
        assert canonical == "123456789"

    def test_invalid_email(self) -> None:
        """Test invalid email."""
        is_valid, error, canonical = validate_email("user@example.ir")
        assert is_valid is False
        assert error is not None
        assert canonical is None

    def test_invalid_phone(self) -> None:
        """Test invalid phone."""
        is_valid, error, canonical = validate_phone("+1234567890")
        assert is_valid is False
        assert error is not None
        assert canonical is None

    def test_invalid_phone_country_code(self) -> None:
        """Test invalid phone country code."""
        is_valid, error, canonical = validate_phone("+1234567890", "IR")
        assert is_valid is False
        assert error is not None
        assert canonical is None

    def test_invalid_username(self) -> None:
        """Test invalid username."""
        is_valid, error, canonical = validate_username("john..doe")
        assert is_valid is False
        assert error is not None
        assert canonical is None

    def test_invalid_username_non_ascii(self) -> None:
        """Test invalid username non ASCII."""
        is_valid, error, canonical = validate_username("سید حسین حسینی")
        assert is_valid is False
        assert error == "Only ASCII usernames are allowed."
        assert canonical is None

    def test_invalid_username_reserved(self) -> None:
        """Test invalid username reserved."""
        is_valid, error, canonical = validate_username("admin")
        assert is_valid is False
        assert error is not None
        assert canonical is None

    def test_invalid_username_bad_word(self) -> None:
        """Test invalid username bad word."""
        is_valid, error, canonical = validate_username("whore")
        assert is_valid is False
        assert error is not None
        assert canonical is None

    def test_invalid_username_too_short(self) -> None:
        """Test invalid username too short."""
        is_valid, error, canonical = validate_username("a")
        assert is_valid is False
        assert error is not None
        assert canonical is None

    def test_invalid_username_too_long(self) -> None:
        """Test invalid username too long."""
        is_valid, error, canonical = validate_username("a" * 31)
        assert is_valid is False
        assert error is not None
        assert canonical is None

    def test_invalid_telegram_id(self) -> None:
        """Test validate_telegram_id function."""
        is_valid, error, canonical = validate_telegram_id("1")
        assert is_valid is False
        assert error is not None
        assert canonical is None

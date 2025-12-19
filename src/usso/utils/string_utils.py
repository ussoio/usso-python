"""String utility functions."""


def get_authorization_scheme_param(
    authorization_header_value: str | None,
) -> tuple[str, str]:
    """
    Extract scheme and parameter from Authorization header.

    Parses an Authorization header value (e.g., "Bearer token123")
    into its scheme and parameter components.

    Args:
        authorization_header_value: The Authorization header value.

    Returns:
        tuple[str, str]: Tuple of (scheme, param).
            Returns ("", "") if value is None.

    """
    if not authorization_header_value:
        return "", ""
    scheme, _, param = authorization_header_value.partition(" ")
    return scheme, param

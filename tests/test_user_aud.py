"""``aud`` may be a list (RFC 7519 4.1.3), e.g. MCP connector tokens."""

from usso.user import UserData


def test_aud_list_is_accepted() -> None:
    """A token bound to several audiences still yields the user."""
    user = UserData(sub="u1", aud=["client-id", "https://getmirza.ir/mcp"])
    assert user.aud == ["client-id", "https://getmirza.ir/mcp"]
    assert user.uid == "u1"


def test_aud_string_still_works() -> None:
    """A single-audience token keeps working."""
    assert UserData(sub="u1", aud="sso").aud == "sso"

"""An empty PROXY setting must mean "no proxy"."""

from unittest.mock import MagicMock

import pytest

from usso import api_key


def _response() -> MagicMock:
    resp = MagicMock()
    resp.json.return_value = {"user_id": "u1"}
    return resp


def test_sync_api_key_treats_empty_proxy_as_no_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``PROXY=`` in .env must not reach httpx as a proxy URL."""
    monkeypatch.setenv("PROXY", "")
    seen: dict = {}

    def fake_post(_url: str, **kwargs: object) -> MagicMock:
        seen.update(kwargs)
        return _response()

    monkeypatch.setattr(api_key.httpx, "post", fake_post)
    monkeypatch.setattr(api_key, "UserData", lambda **kw: kw)
    api_key.fetch_api_key_data("https://x.test/verify", "k")
    assert seen["proxy"] is None


async def test_async_api_key_treats_empty_proxy_as_no_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The async client must also get no proxy for an empty PROXY."""
    monkeypatch.setenv("PROXY", "")
    seen: dict = {}

    class FakeClient:
        def __init__(self, **kwargs: object) -> None:
            seen.update(kwargs)

        async def __aenter__(self) -> "FakeClient":
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def post(self, *_: object, **__: object) -> MagicMock:
            return _response()

    monkeypatch.setattr(api_key.httpx, "AsyncClient", FakeClient)
    monkeypatch.setattr(api_key, "UserData", lambda **kw: kw)
    await api_key.fetch_api_key_data_async("https://x.test/verify", "k")
    assert seen["proxy"] is None

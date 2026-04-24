"""Tests for r53.get_my_ip."""

from unittest.mock import MagicMock, patch
from urllib.error import URLError

import pytest

from r53 import get_my_ip


def _make_urlopen_mock(body: bytes) -> MagicMock:
    """Return a MagicMock that behaves like a urlopen context manager."""
    response = MagicMock()
    response.read.return_value = body
    cm = MagicMock()
    cm.__enter__.return_value = response
    cm.__exit__.return_value = False
    mock = MagicMock(return_value=cm)
    return mock


def test_get_my_ip_returns_stripped_body():
    with patch("r53.request.urlopen", new=_make_urlopen_mock(b"1.2.3.4\n")):
        assert get_my_ip() == "1.2.3.4"


def test_get_my_ip_raises_runtime_error_on_urlerror():
    def raise_urlerror(_url):
        raise URLError("boom")

    with patch("r53.request.urlopen", side_effect=raise_urlerror):
        with pytest.raises(RuntimeError, match="Error retrieving public IP"):
            get_my_ip()

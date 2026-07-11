"""Tests for r53.get_my_ip."""

from unittest.mock import MagicMock, patch
from urllib.error import URLError

import pytest

from r53 import CHECKIP_MAX_BODY_BYTES, CHECKIP_TIMEOUT_SECONDS, get_my_ip


def _make_urlopen_mock(body: bytes) -> MagicMock:
    """Return a MagicMock that behaves like a urlopen context manager."""
    response = MagicMock()
    # Honor the max-bytes read size used by get_my_ip.
    response.read.side_effect = lambda n=-1: body if n < 0 else body[:n]
    cm = MagicMock()
    cm.__enter__.return_value = response
    cm.__exit__.return_value = False
    mock = MagicMock(return_value=cm)
    return mock


def test_get_my_ip_returns_normalized_ipv4():
    with patch("r53.request.urlopen", new=_make_urlopen_mock(b"  1.2.3.4\n")) as mock_open:
        assert get_my_ip() == "1.2.3.4"
        mock_open.assert_called_once()
        _, kwargs = mock_open.call_args
        assert kwargs.get("timeout") == CHECKIP_TIMEOUT_SECONDS


def test_get_my_ip_accepts_ipv6():
    with patch("r53.request.urlopen", new=_make_urlopen_mock(b"2001:db8::1\n")):
        assert get_my_ip() == "2001:db8::1"


def test_get_my_ip_rejects_non_ip_body():
    with patch("r53.request.urlopen", new=_make_urlopen_mock(b"not-an-ip\n")):
        with pytest.raises(RuntimeError, match="non-IP value"):
            get_my_ip()


def test_get_my_ip_rejects_oversized_body():
    body = b"1" * (CHECKIP_MAX_BODY_BYTES + 1)
    with patch("r53.request.urlopen", new=_make_urlopen_mock(body)):
        with pytest.raises(RuntimeError, match="unexpectedly large"):
            get_my_ip()


def test_get_my_ip_raises_runtime_error_on_urlerror():
    def raise_urlerror(*_args, **_kwargs):
        raise URLError("boom")

    with patch("r53.request.urlopen", side_effect=raise_urlerror):
        with pytest.raises(RuntimeError, match="Error retrieving public IP"):
            get_my_ip()
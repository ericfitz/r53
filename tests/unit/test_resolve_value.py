"""Tests for r53.resolve_value."""

from argparse import Namespace
from unittest.mock import patch

import pytest

from r53 import resolve_value


def make_args(*, value=None, eip=None, myip=False, instanceid=None):
    return Namespace(value=value, eip=eip, myip=myip, instanceid=instanceid)


def test_resolve_value_returns_none_when_no_source():
    args = make_args()
    assert resolve_value(args, ec2=object()) is None


def test_resolve_value_returns_plain_value():
    args = make_args(value="1.2.3.4")
    assert resolve_value(args, ec2=object()) == "1.2.3.4"


def test_resolve_value_uses_eip_helper():
    args = make_args(eip="eipalloc-abc")
    fake_ec2 = object()
    with patch("r53.get_ip_from_eip", return_value="9.9.9.9") as mock_fn:
        assert resolve_value(args, ec2=fake_ec2) == "9.9.9.9"
    mock_fn.assert_called_once_with("eipalloc-abc", fake_ec2)


def test_resolve_value_uses_myip_helper():
    args = make_args(myip=True)
    with patch("r53.get_my_ip", return_value="8.8.8.8") as mock_fn:
        assert resolve_value(args, ec2=object()) == "8.8.8.8"
    mock_fn.assert_called_once_with()


def test_resolve_value_uses_instance_helper():
    args = make_args(instanceid="i-123")
    fake_ec2 = object()
    with patch("r53.get_instance_ip", return_value="7.7.7.7") as mock_fn:
        assert resolve_value(args, ec2=fake_ec2) == "7.7.7.7"
    mock_fn.assert_called_once_with("i-123", fake_ec2)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"value": "1.2.3.4", "eip": "eipalloc-abc"},
        {"value": "1.2.3.4", "myip": True},
        {"value": "1.2.3.4", "instanceid": "i-123"},
        {"eip": "eipalloc-abc", "myip": True},
        {"eip": "eipalloc-abc", "instanceid": "i-123"},
        {"myip": True, "instanceid": "i-123"},
    ],
)
def test_resolve_value_rejects_multiple_sources(kwargs):
    args = make_args(**kwargs)
    with pytest.raises(ValueError, match="Specify only one of"):
        resolve_value(args, ec2=object())

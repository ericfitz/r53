"""Tests for r53.infer_record_type."""

import pytest

from r53 import infer_record_type


@pytest.mark.parametrize(
    "explicit_type,value,expected",
    [
        ("A", "1.2.3.4", "A"),
        ("MX", "1.2.3.4", "MX"),
        ("TXT", "anything", "TXT"),
        (None, None, None),
        (None, "1.2.3.4", "A"),
        (None, "0.0.0.0", "A"),
        (None, "255.255.255.255", "A"),
        (None, "::1", "AAAA"),
        (None, "2001:db8::1", "AAAA"),
        (None, "example.com", "CNAME"),
        (None, "sub.example.com", "CNAME"),
    ],
)
def test_infer_record_type_returns_expected(explicit_type, value, expected):
    assert infer_record_type(explicit_type, value) == expected


def test_infer_record_type_raises_on_unparseable_value():
    with pytest.raises(ValueError, match="Cannot infer record type"):
        infer_record_type(None, "not a valid anything !!!")

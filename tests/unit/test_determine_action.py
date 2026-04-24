"""Tests for r53.determine_action decision logic."""

import pytest

from r53 import determine_action


@pytest.mark.parametrize(
    "zone_id,record_name,record_type,value,delete,expected",
    [
        (None, None, None, None, False, "LISTZONES"),
        (None, "foo.example.com", "A", "1.2.3.4", False, "LISTZONES"),
        ("Z123", None, None, None, False, "LIST"),
        ("Z123", "foo.example.com", None, None, False, "DESCRIBE"),
        ("Z123", "foo.example.com", "A", None, True, "DELETE"),
        ("Z123", "foo.example.com", "A", "1.2.3.4", False, "UPSERT"),
        ("Z123", "foo.example.com", "CNAME", "target.example.com", False, "UPSERT"),
        ("Z123", "foo.example.com", "A", "1.2.3.4", True, "UPSERT"),
    ],
)
def test_determine_action_returns_expected(
    zone_id, record_name, record_type, value, delete, expected
):
    assert determine_action(zone_id, record_name, record_type, value, delete) == expected


def test_determine_action_raises_when_upsert_missing_value():
    with pytest.raises(ValueError, match="Must specify value for upserts"):
        determine_action("Z123", "foo.example.com", "A", None, False)

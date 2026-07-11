"""Tests for r53.require_allow_for_dangerous_type."""

import pytest

from r53 import require_allow_for_dangerous_type


@pytest.mark.parametrize(
    "record_type,action,kwargs,should_raise",
    [
        ("A", "UPSERT", {}, False),
        ("NS", "LIST", {}, False),
        ("NS", "DESCRIBE", {}, False),
        ("NS", "UPSERT", {}, True),
        ("NS", "DELETE", {}, True),
        ("NS", "UPSERT", {"allow_ns": True}, False),
        ("SOA", "UPSERT", {}, True),
        ("SOA", "UPSERT", {"allow_soa": True}, False),
        ("CAA", "DELETE", {}, True),
        ("CAA", "DELETE", {"allow_caa": True}, False),
        (None, "UPSERT", {}, False),
    ],
)
def test_require_allow_for_dangerous_type(record_type, action, kwargs, should_raise):
    defaults = {"allow_ns": False, "allow_soa": False, "allow_caa": False}
    defaults.update(kwargs)
    if should_raise:
        with pytest.raises(ValueError, match="Re-run with"):
            require_allow_for_dangerous_type(record_type, action, **defaults)
    else:
        require_allow_for_dangerous_type(record_type, action, **defaults)

"""Tests for r53.build_record_name."""

import pytest

from r53 import build_record_name


@pytest.mark.parametrize(
    "name,zone,expected",
    [
        (None, "example.com", None),
        ("home", "example.com", "home.example.com"),
        ("api.prod", "example.com", "api.prod.example.com"),
        ("home.", "example.com.", "home.example.com"),
        ("HOME", "Example.COM", "HOME.Example.COM"),
    ],
)
def test_build_record_name_ok(name, zone, expected):
    assert build_record_name(name, zone) == expected


@pytest.mark.parametrize(
    "name,zone,match",
    [
        ("", "example.com", "Invalid record name"),
        (".", "example.com", "Invalid record name"),
        ("-bad", "example.com", "Invalid record name"),
        ("home.example.com", "example.com", "already looks fully qualified"),
        ("example.com", "example.com", "already looks fully qualified"),
        ("sub.home.example.com", "example.com", "already looks fully qualified"),
    ],
)
def test_build_record_name_errors(name, zone, match):
    with pytest.raises(ValueError, match=match):
        build_record_name(name, zone)

"""Parametrized tests for r53 validator functions."""

import pytest

from r53 import (
    is_valid_dns_name,
    is_valid_ipv4_address,
    is_valid_ipv6_address,
)


@pytest.mark.parametrize(
    "address,expected",
    [
        ("1.2.3.4", True),
        ("0.0.0.0", True),
        ("255.255.255.255", True),
        ("192.168.1.1", True),
        ("256.0.0.1", False),
        ("1.2.3", False),
        ("1.2.3.4.5", False),
        ("", False),
        ("abc.def.ghi.jkl", False),
        ("::1", False),
        ("1.2.3.4 ", False),
    ],
)
def test_is_valid_ipv4_address(address, expected):
    assert is_valid_ipv4_address(address) is expected


def test_is_valid_ipv4_address_non_string():
    assert is_valid_ipv4_address(None) is False


@pytest.mark.parametrize(
    "address,expected",
    [
        ("::1", True),
        ("2001:db8::1", True),
        ("fe80::1", True),
        ("0:0:0:0:0:0:0:1", True),
        ("2001:0db8:0000:0000:0000:ff00:0042:8329", True),
        ("1.2.3.4", False),
        ("not-an-address", False),
        ("", False),
        ("gggg::1", False),
        # Zone/scope ID syntax: accepted on platforms whose inet_pton
        # tolerates the "%zone" suffix (macOS, Linux glibc). Pinning the
        # current behavior here so a silent change on a new platform is
        # caught by a test, not by a user report.
        ("fe80::1%eth0", True),
    ],
)
def test_is_valid_ipv6_address(address, expected):
    assert is_valid_ipv6_address(address) is expected


def test_is_valid_ipv6_address_non_string():
    assert is_valid_ipv6_address(None) is False


@pytest.mark.parametrize(
    "name,expected",
    [
        ("example.com", True),
        ("example.com.", True),
        ("sub.example.com", True),
        ("a.b.c.d.example.com", True),
        ("xn--bcher-kva.example", True),
        ("EXAMPLE.COM", True),
        ("", False),
        ("-example.com", False),
        ("example-.com", False),
        ("exa..mple.com", False),
        ("a" * 64 + ".com", False),
        (("a" * 63 + ".") * 4 + "com", False),
        (".", False),
        # 253-char name (no trailing dot): the RFC 1035 maximum.
        (("a" * 63 + ".") * 3 + "a" * 61, True),
        # 253-char name with trailing dot: 254 chars input, stripped to 253.
        (("a" * 63 + ".") * 3 + "a" * 61 + ".", True),
        # 254-char name (no trailing dot): one over the limit.
        (("a" * 63 + ".") * 3 + "a" * 62, False),
        # 256-char, trailing dot, still over after strip (255 chars).
        (("a" * 63 + ".") * 4, False),
    ],
)
def test_is_valid_dns_name(name, expected):
    assert is_valid_dns_name(name) is expected


def test_is_valid_dns_name_non_string():
    assert is_valid_dns_name(None) is False

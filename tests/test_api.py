"""Unit tests for counter/rate math and parsing (no SNMP agent needed)."""

from __future__ import annotations

from custom_components.sophos_sfos.api import SfosMonitor, parse_expiry, to_number


def test_to_number() -> None:
    assert to_number("0.42") == 0.42
    assert to_number(17) == 17.0
    assert to_number("n/a") is None
    assert to_number(None) is None


def test_parse_expiry() -> None:
    assert parse_expiry("Dec 31 2999").year == 2999
    assert parse_expiry("2027-01-15").month == 1
    assert parse_expiry("") is None
    assert parse_expiry("Unlimited") is None


def test_rate_wrap_and_reset() -> None:
    mon = SfosMonitor(client=None)  # type: ignore[arg-type]
    assert mon._rate("k", 100, 0.0, 64) is None  # first sample
    assert mon._rate("k", 1100, 10.0, 64) == 100.0
    # 32-bit wrap
    mon._rate("w", 2**32 - 1000, 0.0, 32)
    assert mon._rate("w", 1000, 1.0, 32) == 2000.0
    # 64-bit "decrease" is a reset (reboot), not a wrap
    mon._rate("r", 10_000, 0.0, 64)
    assert mon._rate("r", 50, 1.0, 64) is None
    assert mon._rate("r", 150, 2.0, 64) == 100.0

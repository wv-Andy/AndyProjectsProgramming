"""Tests for the password auditor.

The entropy maths and the k-anonymity hashing are offline and deterministic.
The one network test is marked and skips without connectivity.
"""

from __future__ import annotations

import hashlib

import pytest

# --- Character pool and entropy -------------------------------------------


@pytest.mark.parametrize(
    ("password", "pool"),
    [
        ("abcdef", 26),
        ("ABCDEF", 26),
        ("abcABC", 52),
        ("abc123", 36),
        ("abcABC123", 62),
        ("abc!@#", 59),
        ("aA1!", 95),
        ("", 0),
    ],
)
def test_character_pool(pwaudit, password, pool):
    assert pwaudit.character_pool(password) == pool


def test_entropy_grows_with_length(pwaudit):
    short = pwaudit.entropy_bits("aaaa")
    long = pwaudit.entropy_bits("aaaaaaaa")
    assert long > short


def test_entropy_grows_with_pool(pwaudit):
    narrow = pwaudit.entropy_bits("aaaaaaaa")
    wide = pwaudit.entropy_bits("aA1!aA1!")
    assert wide > narrow


def test_entropy_of_empty_is_zero(pwaudit):
    assert pwaudit.entropy_bits("") == 0.0


def test_entropy_matches_the_formula(pwaudit):
    import math

    # 8 lowercase characters, pool of 26.
    expected = 8 * math.log2(26)
    assert pwaudit.entropy_bits("abcdefgh") == pytest.approx(expected)


# --- Weakness patterns ----------------------------------------------------


def test_flags_a_common_password(pwaudit):
    warnings = pwaudit.find_patterns("password")
    assert any("common" in warning for warning in warnings)


def test_flags_sequential_digits(pwaudit):
    assert any("sequential" in warning for warning in pwaudit.find_patterns("foo123bar"))


def test_flags_keyboard_runs(pwaudit):
    assert any("keyboard" in warning.lower() for warning in pwaudit.find_patterns("qwerty!!"))


def test_flags_repeated_characters(pwaudit):
    assert any("repeated" in warning for warning in pwaudit.find_patterns("aaaXYZ12"))


def test_flags_the_word_digit_symbol_pattern(pwaudit):
    assert any("predictable" in warning for warning in pwaudit.find_patterns("Summer2024!"))


def test_a_strong_random_password_has_few_warnings(pwaudit):
    warnings = pwaudit.find_patterns("9xKq2mVz7Lw4pReT")
    assert warnings == []


# --- Bands and crack time -------------------------------------------------


@pytest.mark.parametrize(
    ("entropy", "band"),
    [(20, "very weak"), (30, "weak"), (50, "reasonable"), (80, "strong"), (130, "very strong")],
)
def test_band_for(pwaudit, entropy, band):
    assert pwaudit.band_for(entropy) == band


def test_crack_time_is_instant_for_zero(pwaudit):
    assert pwaudit.crack_time_estimate(0) == "instant"


def test_crack_time_grows_with_entropy(pwaudit):
    weak = pwaudit.crack_time_estimate(20)
    strong = pwaudit.crack_time_estimate(120)
    assert weak != strong
    assert "universe" in pwaudit.crack_time_estimate(300)


# --- k-anonymity ----------------------------------------------------------


def test_prefix_is_five_hex_chars_and_matches_sha1(pwaudit):
    prefix, suffix = pwaudit.sha1_prefix_and_suffix("password")
    full = hashlib.sha1(b"password").hexdigest().upper()
    assert len(prefix) == 5
    assert prefix + suffix == full


def test_only_the_prefix_would_ever_be_sent(pwaudit):
    """The suffix stays local; that is the whole privacy guarantee."""
    prefix, suffix = pwaudit.sha1_prefix_and_suffix("hunter2")
    # The prefix alone cannot reconstruct the password or the full hash.
    assert len(prefix) == 5
    assert len(suffix) == 35


def test_parse_hibp_response_finds_a_match(pwaudit):
    # The API returns SUFFIX:COUNT lines. This is the real suffix for "password".
    _, suffix = pwaudit.sha1_prefix_and_suffix("password")
    body = f"0000000000000000000000000000000000A:3\r\n{suffix}:99\r\nFFFF:1"
    assert pwaudit.parse_hibp_response(body, suffix) == 99


def test_parse_hibp_response_returns_zero_when_absent(pwaudit):
    body = "0000000000000000000000000000000000A:3\r\nFFFF:1"
    assert pwaudit.parse_hibp_response(body, "DEADBEEF") == 0


# --- CLI ------------------------------------------------------------------


def test_cli_rejects_an_empty_password(pwaudit):
    assert pwaudit.main(["", "--no-breach-check"]) == 2


def test_cli_flags_a_weak_password(pwaudit):
    assert pwaudit.main(["abc", "--no-breach-check"]) == 1


def test_cli_passes_a_strong_password(pwaudit):
    assert pwaudit.main(["9x!Kq2#mVz7@Lw4pReT8&", "--no-breach-check"]) == 0


@pytest.mark.network
def test_breach_check_finds_a_known_password(pwaudit):
    try:
        result = pwaudit.check_breach("password", timeout=10)
    except OSError as exc:
        pytest.skip(f"Network unavailable: {exc}")
    if "failed" in result.detail or "HTTP" in result.detail:
        pytest.skip(result.detail)
    assert result.found is True
    assert result.count > 0


@pytest.mark.network
def test_breach_check_clears_a_random_password(pwaudit):
    import secrets

    random_password = secrets.token_urlsafe(24)
    try:
        result = pwaudit.check_breach(random_password, timeout=10)
    except OSError as exc:
        pytest.skip(f"Network unavailable: {exc}")
    if "failed" in result.detail or "HTTP" in result.detail:
        pytest.skip(result.detail)
    assert result.found is False

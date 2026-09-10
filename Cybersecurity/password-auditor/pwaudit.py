"""Password strength and breach auditor.

Two questions, answered separately:

1. How hard is this password to guess? Measured as entropy, based on the pool of
   characters it draws from and its length, not the usual "one uppercase, one
   symbol" checklist that rewards `Password1!`.
2. Has it appeared in a known breach? Checked against the Have I Been Pwned range
   API using k-anonymity, so the password never leaves the machine.

The k-anonymity trick is the interesting part: you hash the password with SHA-1,
send only the first five hex characters, and get back every suffix that shares
that prefix. You match locally. The service never sees enough to know your
password, and it never sees the full hash.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import http.client
import math
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass

HIBP_HOST = "api.pwnedpasswords.com"

# Character pools, used to estimate the search space.
POOL_LOWER = 26
POOL_UPPER = 26
POOL_DIGITS = 10
POOL_SYMBOLS = 33  # printable ASCII punctuation and space

# A tiny built-in list of the passwords that top every breach corpus. This is a
# cheap offline check before spending a network round trip.
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "12345678", "12345", "qwerty",
    "abc123", "password1", "111111", "letmein", "admin", "welcome",
    "monkey", "dragon", "iloveyou", "1234567890", "qwerty123", "000000",
}

STRENGTH_BANDS = (
    (28, "very weak"),
    (36, "weak"),
    (60, "reasonable"),
    (128, "strong"),
)


@dataclass
class Strength:
    entropy_bits: float
    pool_size: int
    length: int
    band: str
    warnings: list[str]


@dataclass
class BreachResult:
    found: bool
    count: int
    detail: str


def character_pool(password: str) -> int:
    """Estimate the size of the character set the password draws from."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += POOL_LOWER
    if re.search(r"[A-Z]", password):
        pool += POOL_UPPER
    if re.search(r"[0-9]", password):
        pool += POOL_DIGITS
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += POOL_SYMBOLS
    return pool


def entropy_bits(password: str) -> float:
    """Shannon entropy of the search space: length times log2 of the pool.

    This is the theoretical work to brute-force a password of this shape. It is
    an upper bound: a password drawn from a small pool of dictionary words has
    far less real entropy than its length suggests, which is what the warnings
    are for.
    """
    pool = character_pool(password)
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def find_patterns(password: str) -> list[str]:
    """Spot the shapes that make a password weaker than its entropy claims."""
    warnings: list[str] = []
    lowered = password.lower()

    if lowered in COMMON_PASSWORDS:
        warnings.append("This is one of the most common passwords in every breach corpus")

    if len(password) < 12:
        warnings.append(f"Only {len(password)} characters; 12 or more is the usual advice")

    if password and password == password[0] * len(password):
        warnings.append("Every character is the same")

    if re.search(r"(.)\1\1", password):
        warnings.append("Contains a character repeated three or more times")

    if re.search(r"(?:012|123|234|345|456|567|678|789|890)", password):
        warnings.append("Contains a run of sequential digits")

    if re.search(r"(?:abc|bcd|cde|def|efg|qwe|wer|ert|asd|sdf|zxc)", lowered):
        warnings.append("Contains a keyboard or alphabet run")

    if re.fullmatch(r"[a-zA-Z]+\d{1,4}[!@#$]?", password):
        warnings.append("Follows the predictable word-then-digits-then-symbol pattern")

    return warnings


def band_for(entropy: float) -> str:
    for threshold, label in STRENGTH_BANDS:
        if entropy < threshold:
            return label
    return "very strong"


def assess_strength(password: str) -> Strength:
    entropy = entropy_bits(password)
    return Strength(
        entropy_bits=round(entropy, 1),
        pool_size=character_pool(password),
        length=len(password),
        band=band_for(entropy),
        warnings=find_patterns(password),
    )


def crack_time_estimate(entropy: float, guesses_per_second: float = 1e10) -> str:
    """Rough offline crack time at a given guessing rate.

    The default of ten billion guesses a second is a plausible figure for a
    single modern GPU against a fast hash. The average attacker needs half the
    space, hence the 2^(bits - 1).
    """
    if entropy <= 0:
        return "instant"
    seconds = (2 ** (entropy - 1)) / guesses_per_second

    units = (
        ("years", 60 * 60 * 24 * 365),
        ("days", 60 * 60 * 24),
        ("hours", 60 * 60),
        ("minutes", 60),
        ("seconds", 1),
    )
    if seconds < 1:
        return "instant"

    years = seconds / (60 * 60 * 24 * 365)
    # The universe is about 1.4e10 years old; past that, precision is theatre.
    if years > 1e14:
        return "longer than the age of the universe"
    if years >= 1e9:
        return f"{years / 1e9:.0f} billion years"
    if years >= 1e6:
        return f"{years / 1e6:.0f} million years"
    if years >= 1:
        return f"{years:,.0f} years"

    for name, size in units:
        if seconds >= size:
            return f"{seconds / size:.0f} {name}"
    return "instant"


def sha1_prefix_and_suffix(password: str) -> tuple[str, str]:
    """Return the 5-char prefix sent to the API and the suffix matched locally.

    SHA-1 is broken for collision resistance, which does not matter here: the API
    is a lookup table keyed on the hash, not a security boundary. The privacy
    comes from only ever sending the prefix.
    """
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


def parse_hibp_response(body: str, wanted_suffix: str) -> int:
    """Find the wanted suffix in the API's suffix:count list."""
    for line in body.splitlines():
        suffix, _, count = line.strip().partition(":")
        if suffix == wanted_suffix:
            try:
                return int(count)
            except ValueError:
                return 0
    return 0


def check_breach(password: str, *, timeout: float = 10.0) -> BreachResult:
    """Query Have I Been Pwned using k-anonymity."""
    prefix, suffix = sha1_prefix_and_suffix(password)

    try:
        connection = http.client.HTTPSConnection(HIBP_HOST, timeout=timeout)
        try:
            connection.request(
                "GET",
                f"/range/{prefix}",
                headers={"User-Agent": "password-auditor/1.0", "Add-Padding": "true"},
            )
            response = connection.getresponse()
            body = response.read().decode("utf-8", errors="replace")
            status = response.status
        finally:
            connection.close()
    except OSError as exc:
        return BreachResult(found=False, count=0, detail=f"Breach check failed: {exc}")

    if status != 200:
        return BreachResult(found=False, count=0, detail=f"API returned HTTP {status}")

    count = parse_hibp_response(body, suffix)
    if count > 0:
        return BreachResult(
            found=True,
            count=count,
            detail=f"Seen {count:,} time(s) in known breaches. Do not use it.",
        )
    return BreachResult(found=False, count=0, detail="Not found in any known breach.")


def print_report(password: str, strength: Strength, breach: BreachResult | None) -> None:
    print("\nPassword audit")
    print("=" * 56)
    print(f"Length:       {strength.length}")
    print(f"Character set: {strength.pool_size} possible characters")
    print(f"Entropy:      {strength.entropy_bits} bits ({strength.band})")
    print(f"Crack time:   ~{crack_time_estimate(strength.entropy_bits)} at 10 billion guesses/sec")

    if strength.warnings:
        print(f"\nWeaknesses ({len(strength.warnings)}):")
        for warning in strength.warnings:
            print(f"  [!] {warning}")

    if breach is not None:
        print()
        marker = "[!]" if breach.found else "[ok]"
        print(f"{marker} {breach.detail}")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit a password's strength and breach status",
        epilog="The password is never sent anywhere. Only a 5-character hash "
        "prefix is, using k-anonymity.",
    )
    parser.add_argument(
        "password",
        nargs="?",
        help="Password to audit. Omit it to be prompted without echo.",
    )
    parser.add_argument(
        "--no-breach-check",
        action="store_true",
        help="Skip the online breach check and assess strength only",
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0, help="Breach-check timeout in seconds"
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    password = args.password
    if password is None:
        try:
            password = getpass.getpass("Password (input hidden): ")
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.", file=sys.stderr)
            return 2

    if not password:
        print("[!] No password given.", file=sys.stderr)
        return 2

    strength = assess_strength(password)
    breach = None if args.no_breach_check else check_breach(password, timeout=args.timeout)

    print_report(password, strength, breach)

    # Exit non-zero if the password is breached or very weak, so the tool can
    # gate a script.
    if breach is not None and breach.found:
        return 1
    if strength.band in ("very weak", "weak"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

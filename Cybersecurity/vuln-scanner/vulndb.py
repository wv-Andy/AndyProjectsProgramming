"""Version matching against a local vulnerability feed.

The matching logic is separate from any network code so it can be tested on its
own. A feed entry names a product, an affected version range and a CVE; a
detected service names a product and a version. The job is to decide whether a
version falls inside a range, which needs a real version comparison, not string
equality.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# CVSS v3 qualitative bands, from the specification.
SEVERITY_BANDS = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
)


class FeedError(ValueError):
    """Raised when the vulnerability feed cannot be loaded."""


@dataclass
class Vulnerability:
    cve: str
    product: str
    version_start: str | None
    version_end: str | None
    start_inclusive: bool
    end_inclusive: bool
    cvss: float
    description: str

    @property
    def severity(self) -> str:
        for threshold, label in SEVERITY_BANDS:
            if self.cvss >= threshold:
                return label
        return "none"


@dataclass
class Match:
    vulnerability: Vulnerability
    detected_version: str
    port: int | None = None


@dataclass
class DetectedService:
    product: str
    version: str
    port: int | None = None
    extra: dict = field(default_factory=dict)


def parse_version(text: str) -> tuple[int, ...]:
    """Turn a version string into a comparable tuple of integers.

    ``1.2.13`` becomes ``(1, 2, 13)``. Trailing text like ``2.4.49p1`` keeps the
    numeric run and drops the rest, which is enough to place it in a range.
    """
    numbers = re.findall(r"\d+", text)
    if not numbers:
        return (0,)
    return tuple(int(number) for number in numbers)


def compare_versions(left: str, right: str) -> int:
    """Return -1, 0 or 1 comparing two version strings numerically."""
    a = parse_version(left)
    b = parse_version(right)
    # Pad the shorter tuple with zeros so 1.2 and 1.2.0 compare equal.
    length = max(len(a), len(b))
    a += (0,) * (length - len(a))
    b += (0,) * (length - len(b))
    if a < b:
        return -1
    if a > b:
        return 1
    return 0


def version_in_range(
    version: str,
    start: str | None,
    end: str | None,
    *,
    start_inclusive: bool,
    end_inclusive: bool,
) -> bool:
    """Decide whether a version falls inside an affected range."""
    if start is not None:
        comparison = compare_versions(version, start)
        if comparison < 0 or (comparison == 0 and not start_inclusive):
            return False
    if end is not None:
        comparison = compare_versions(version, end)
        if comparison > 0 or (comparison == 0 and not end_inclusive):
            return False
    return True


def load_feed(path: Path) -> list[Vulnerability]:
    """Load a JSON vulnerability feed into Vulnerability records."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise FeedError(f"Could not read feed {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise FeedError(f"Feed {path} is not valid JSON: {exc}") from exc

    if not isinstance(data, list):
        raise FeedError("Feed must be a list of vulnerability entries")

    vulnerabilities: list[Vulnerability] = []
    for index, entry in enumerate(data):
        try:
            vulnerabilities.append(
                Vulnerability(
                    cve=entry["cve"],
                    product=entry["product"].lower(),
                    version_start=entry.get("version_start"),
                    version_end=entry.get("version_end"),
                    start_inclusive=entry.get("start_inclusive", True),
                    end_inclusive=entry.get("end_inclusive", False),
                    cvss=float(entry.get("cvss", 0.0)),
                    description=entry.get("description", ""),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise FeedError(f"Entry {index} is malformed: {exc}") from exc

    return vulnerabilities


def match_service(
    service: DetectedService, feed: list[Vulnerability]
) -> list[Match]:
    """Find every feed entry whose product and range cover the service."""
    matches: list[Match] = []
    product = service.product.lower()

    for vulnerability in feed:
        if vulnerability.product != product:
            continue
        if version_in_range(
            service.version,
            vulnerability.version_start,
            vulnerability.version_end,
            start_inclusive=vulnerability.start_inclusive,
            end_inclusive=vulnerability.end_inclusive,
        ):
            matches.append(
                Match(
                    vulnerability=vulnerability,
                    detected_version=service.version,
                    port=service.port,
                )
            )

    return matches


def match_all(
    services: list[DetectedService], feed: list[Vulnerability]
) -> list[Match]:
    """Match every detected service, ordered by severity, most serious first."""
    matches: list[Match] = []
    for service in services:
        matches.extend(match_service(service, feed))
    matches.sort(key=lambda match: match.vulnerability.cvss, reverse=True)
    return matches


# A banner like "Apache/2.4.49 (Unix)" or "OpenSSH_7.4" carries the product and
# version. These patterns pull them out.
BANNER_PATTERNS = (
    (re.compile(r"Apache/(\d+\.\d+\.\d+)", re.IGNORECASE), "apache"),
    (re.compile(r"nginx/(\d+\.\d+\.\d+)", re.IGNORECASE), "nginx"),
    (re.compile(r"OpenSSH[_/](\d+\.\d+)", re.IGNORECASE), "openssh"),
    (re.compile(r"vsftpd (\d+\.\d+\.\d+)", re.IGNORECASE), "vsftpd"),
    (re.compile(r"ProFTPD (\d+\.\d+\.\d+)", re.IGNORECASE), "proftpd"),
    (re.compile(r"Exim (\d+\.\d+)", re.IGNORECASE), "exim"),
    (re.compile(r"PHP/(\d+\.\d+\.\d+)", re.IGNORECASE), "php"),
)


def parse_banner(banner: str, port: int | None = None) -> DetectedService | None:
    """Pull a product and version out of a service banner, if one is there."""
    for pattern, product in BANNER_PATTERNS:
        found = pattern.search(banner)
        if found:
            return DetectedService(product=product, version=found.group(1), port=port)
    return None

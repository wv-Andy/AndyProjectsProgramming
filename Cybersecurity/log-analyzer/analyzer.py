"""Log parser and anomaly reporter.

Reads authentication or web access logs and reports what stands out: brute-force
attempts, scanning behaviour, error bursts and the busiest clients.

This is the defensive half of the toolkit. The scanner and the enumerator make
noise; this reads the noise somebody else made.

Files are streamed line by line, so a multi-gigabyte log costs no more memory
than a small one.
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import unquote

# sshd and sudo failures, as written by OpenSSH into auth.log.
AUTH_FAILURE = re.compile(
    r"(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2}).*?"
    r"(?:Failed password for(?: invalid user)?\s+(?P<user>\S+)|"
    r"Invalid user\s+(?P<invalid_user>\S+)|"
    r"authentication failure).*?"
    r"(?:from\s+|rhost=)(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

AUTH_SUCCESS = re.compile(
    r"(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2}).*?"
    r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

# The combined log format nginx and Apache both default to.
ACCESS_LOG = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: (?P<protocol>[^"]*))?" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?'
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Paths that only a scanner asks for.
SUSPICIOUS_PATHS = (
    "/.env", "/.git", "/wp-login", "/wp-admin", "/phpmyadmin", "/admin",
    "/.aws", "/config", "/backup", "/shell", "/.ssh", "/actuator",
    "/solr", "/struts", "/cgi-bin", "/etc/passwd", "/manager/html",
)

SCANNER_AGENTS = (
    "nmap", "nikto", "sqlmap", "masscan", "zgrab", "curl", "python-requests", "gobuster",
)

# Payload shapes that show up in injection attempts.
INJECTION_PATTERNS = (
    (re.compile(r"(?i)union\s+select"), "SQL injection: UNION SELECT"),
    (re.compile(r"(?i)'\s*or\s*'?1'?\s*=\s*'?1"), "SQL injection: OR 1=1"),
    (re.compile(r"(?i)<script"), "Cross-site scripting: script tag"),
    (re.compile(r"(?i)(\.\./){2,}"), "Path traversal"),
    (re.compile(r"(?i)/etc/passwd"), "Path traversal: /etc/passwd"),
    (re.compile(r"(?i);\s*(cat|wget|curl|bash|sh)\s"), "Command injection"),
)


@dataclass
class Thresholds:
    """How much of a thing counts as an anomaly."""

    failed_logins: int = 5
    brute_force_window_minutes: int = 5
    brute_force_attempts: int = 10
    not_found_burst: int = 20
    error_rate_percent: float = 10.0
    top_count: int = 10


@dataclass
class AuthEvent:
    timestamp: datetime | None
    ip: str
    user: str
    success: bool


@dataclass
class AccessEvent:
    timestamp: datetime | None
    ip: str
    method: str
    path: str
    status: int
    size: int
    agent: str


@dataclass
class Finding:
    severity: str
    category: str
    summary: str
    evidence: list[str] = field(default_factory=list)


def open_log(path: Path) -> Iterator[str]:
    """Yield lines from a log file, transparently handling gzip."""
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            yield from handle
    else:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            yield from handle


def parse_syslog_time(month: str, day: str, time_text: str, year: int) -> datetime | None:
    """Syslog omits the year, so the caller has to supply one."""
    try:
        hour, minute, second = (int(part) for part in time_text.split(":"))
        return datetime(year, MONTHS[month], int(day), hour, minute, second)
    except (KeyError, ValueError):
        return None


def parse_access_time(text: str) -> datetime | None:
    try:
        return datetime.strptime(text.split()[0], "%d/%b/%Y:%H:%M:%S")
    except (ValueError, IndexError):
        return None


def parse_auth_log(lines: Iterable[str], year: int) -> tuple[list[AuthEvent], int]:
    """Extract authentication successes and failures."""
    events: list[AuthEvent] = []
    unparsed = 0

    for line in lines:
        if not line.strip():
            continue

        match = AUTH_FAILURE.search(line)
        if match:
            groups = match.groupdict()
            events.append(
                AuthEvent(
                    timestamp=parse_syslog_time(
                        groups["month"], groups["day"], groups["time"], year
                    ),
                    ip=groups["ip"],
                    user=groups.get("user") or groups.get("invalid_user") or "unknown",
                    success=False,
                )
            )
            continue

        match = AUTH_SUCCESS.search(line)
        if match:
            groups = match.groupdict()
            events.append(
                AuthEvent(
                    timestamp=parse_syslog_time(
                        groups["month"], groups["day"], groups["time"], year
                    ),
                    ip=groups["ip"],
                    user=groups["user"],
                    success=True,
                )
            )
            continue

        unparsed += 1

    return events, unparsed


def parse_access_log(lines: Iterable[str]) -> tuple[list[AccessEvent], int]:
    """Extract requests from a combined-format access log."""
    events: list[AccessEvent] = []
    unparsed = 0

    for line in lines:
        if not line.strip():
            continue
        match = ACCESS_LOG.match(line)
        if not match:
            unparsed += 1
            continue

        groups = match.groupdict()
        try:
            size = int(groups["size"])
        except (TypeError, ValueError):
            size = 0

        events.append(
            AccessEvent(
                timestamp=parse_access_time(groups["timestamp"]),
                ip=groups["ip"],
                method=groups["method"],
                path=groups["path"],
                status=int(groups["status"]),
                size=size,
                agent=groups.get("agent") or "",
            )
        )

    return events, unparsed


def find_brute_force(
    events: Sequence[AuthEvent], thresholds: Thresholds
) -> list[Finding]:
    """Flag repeated failures, and the rapid bursts that mean automation."""
    findings: list[Finding] = []
    failures_by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if not event.success:
            failures_by_ip[event.ip].append(event)

    window = timedelta(minutes=thresholds.brute_force_window_minutes)

    for ip, failures in sorted(
        failures_by_ip.items(), key=lambda item: len(item[1]), reverse=True
    ):
        if len(failures) < thresholds.failed_logins:
            continue

        users = Counter(failure.user for failure in failures)
        stamped = sorted(
            failure.timestamp for failure in failures if failure.timestamp is not None
        )

        # A sliding window over the timestamps: how many attempts ever landed
        # inside `window` of each other.
        peak = 0
        start = 0
        for end in range(len(stamped)):
            while stamped[end] - stamped[start] > window:
                start += 1
            peak = max(peak, end - start + 1)

        rapid = peak >= thresholds.brute_force_attempts
        severity = "high" if rapid else "medium"
        summary = f"{ip} failed to authenticate {len(failures)} times"
        if rapid:
            summary += (
                f", peaking at {peak} attempts inside "
                f"{thresholds.brute_force_window_minutes} minutes"
            )

        evidence = [f"users tried: {', '.join(user for user, _ in users.most_common(5))}"]
        if len(users) >= 5:
            evidence.append(f"{len(users)} distinct usernames, which suggests a wordlist")
        if stamped:
            evidence.append(f"first {stamped[0]:%Y-%m-%d %H:%M:%S}, last {stamped[-1]:%H:%M:%S}")

        findings.append(
            Finding(severity=severity, category="brute-force", summary=summary, evidence=evidence)
        )

    return findings


def find_successful_logins_after_failures(
    events: Sequence[AuthEvent], thresholds: Thresholds
) -> list[Finding]:
    """A success from an address that just failed repeatedly is the worst case."""
    findings: list[Finding] = []
    failures = Counter(event.ip for event in events if not event.success)

    for event in events:
        if not event.success:
            continue
        if failures[event.ip] >= thresholds.failed_logins:
            findings.append(
                Finding(
                    severity="critical",
                    category="compromise",
                    summary=(
                        f"{event.ip} authenticated successfully as {event.user} "
                        f"after {failures[event.ip]} failures"
                    ),
                    evidence=[
                        "A guessed password is the likeliest explanation",
                        "Rotate this account's credentials and check what the session did",
                    ],
                )
            )

    return findings


def find_scanning(events: Sequence[AccessEvent], thresholds: Thresholds) -> list[Finding]:
    """Bursts of 404s, and requests for paths only a scanner wants."""
    findings: list[Finding] = []

    not_found: dict[str, list[str]] = defaultdict(list)
    for event in events:
        if event.status == 404:
            not_found[event.ip].append(event.path)

    for ip, paths in sorted(not_found.items(), key=lambda item: len(item[1]), reverse=True):
        if len(paths) < thresholds.not_found_burst:
            continue
        unique = len(set(paths))
        findings.append(
            Finding(
                severity="medium",
                category="scanning",
                summary=f"{ip} triggered {len(paths)} not-found responses across {unique} paths",
                evidence=[f"examples: {', '.join(sorted(set(paths))[:5])}"],
            )
        )

    probes: dict[str, set[str]] = defaultdict(set)
    for event in events:
        lowered = event.path.lower()
        for marker in SUSPICIOUS_PATHS:
            if marker in lowered:
                probes[event.ip].add(event.path)

    for ip, paths in sorted(probes.items(), key=lambda item: len(item[1]), reverse=True):
        findings.append(
            Finding(
                severity="high" if len(paths) > 3 else "medium",
                category="scanning",
                summary=f"{ip} requested {len(paths)} sensitive path(s)",
                evidence=[f"paths: {', '.join(sorted(paths)[:6])}"],
            )
        )

    return findings


def find_injection_attempts(events: Sequence[AccessEvent]) -> list[Finding]:
    """Look for injection payload shapes in the request path.

    The path is URL-decoded first. Attackers encode payloads precisely so a
    naive substring match misses them, so ``union%20select`` has to be compared
    as ``union select``. Decoding twice catches the double-encoding trick.
    """
    hits: dict[tuple[str, str], list[str]] = defaultdict(list)

    for event in events:
        candidates = {event.path}
        decoded = unquote(event.path)
        candidates.add(decoded)
        candidates.add(unquote(decoded))

        for pattern, label in INJECTION_PATTERNS:
            if any(pattern.search(candidate) for candidate in candidates):
                hits[(event.ip, label)].append(event.path)

    findings = []
    for (ip, label), paths in sorted(hits.items(), key=lambda item: len(item[1]), reverse=True):
        findings.append(
            Finding(
                severity="high",
                category="injection",
                summary=f"{ip} sent {len(paths)} request(s) matching {label}",
                evidence=[f"example: {paths[0][:120]}"],
            )
        )
    return findings


def find_scanner_agents(events: Sequence[AccessEvent]) -> list[Finding]:
    counts: dict[tuple[str, str], int] = Counter()
    for event in events:
        lowered = event.agent.lower()
        for marker in SCANNER_AGENTS:
            if marker in lowered:
                counts[(event.ip, marker)] += 1

    return [
        Finding(
            severity="low",
            category="tooling",
            summary=f"{ip} sent {count} request(s) with a {marker} user agent",
            evidence=["An honest user agent is a hint, not proof, since it is trivially forged"],
        )
        for (ip, marker), count in sorted(counts.items(), key=lambda item: -item[1])
    ]


def find_error_rate(events: Sequence[AccessEvent], thresholds: Thresholds) -> list[Finding]:
    if not events:
        return []
    server_errors = sum(1 for event in events if 500 <= event.status < 600)
    rate = server_errors * 100 / len(events)
    if rate < thresholds.error_rate_percent:
        return []
    return [
        Finding(
            severity="medium",
            category="availability",
            summary=(
                f"{rate:.1f}% of requests returned a server error "
                f"({server_errors} of {len(events)})"
            ),
            evidence=["A sustained 5xx rate points at a failing backend, not an attacker"],
        )
    ]


def summarise_access(events: Sequence[AccessEvent], thresholds: Thresholds) -> dict:
    statuses = Counter(event.status for event in events)
    timestamps = [event.timestamp for event in events if event.timestamp]
    return {
        "requests": len(events),
        "unique_clients": len({event.ip for event in events}),
        "top_clients": Counter(event.ip for event in events).most_common(thresholds.top_count),
        "top_paths": Counter(event.path for event in events).most_common(thresholds.top_count),
        "status_codes": dict(sorted(statuses.items())),
        "bytes_sent": sum(event.size for event in events),
        "first_seen": min(timestamps).isoformat() if timestamps else None,
        "last_seen": max(timestamps).isoformat() if timestamps else None,
    }


def summarise_auth(events: Sequence[AuthEvent], thresholds: Thresholds) -> dict:
    failures = [event for event in events if not event.success]
    successes = [event for event in events if event.success]
    return {
        "events": len(events),
        "failures": len(failures),
        "successes": len(successes),
        "unique_clients": len({event.ip for event in events}),
        "top_offenders": Counter(event.ip for event in failures).most_common(thresholds.top_count),
        "targeted_users": Counter(
            event.user for event in failures
        ).most_common(thresholds.top_count),
    }


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def detect_format(lines: Sequence[str]) -> str:
    """Guess the log format from the first lines that parse."""
    for line in lines[:200]:
        if ACCESS_LOG.match(line):
            return "access"
        if AUTH_FAILURE.search(line) or AUTH_SUCCESS.search(line):
            return "auth"
    return "unknown"


def analyse(
    lines: Sequence[str], log_format: str, thresholds: Thresholds, year: int
) -> tuple[list[Finding], dict, int]:
    if log_format == "auth":
        events, unparsed = parse_auth_log(lines, year)
        findings = find_brute_force(events, thresholds)
        findings += find_successful_logins_after_failures(events, thresholds)
        summary = summarise_auth(events, thresholds)
    else:
        events, unparsed = parse_access_log(lines)
        findings = find_scanning(events, thresholds)
        findings += find_injection_attempts(events)
        findings += find_error_rate(events, thresholds)
        findings += find_scanner_agents(events)
        summary = summarise_access(events, thresholds)

    findings.sort(key=lambda finding: SEVERITY_ORDER.get(finding.severity, 9))
    return findings, summary, unparsed


def print_report(
    path: Path, log_format: str, findings: Sequence[Finding], summary: dict, unparsed: int
) -> None:
    print(f"\nLog analysis: {path.name}")
    print("=" * 68)
    print(f"Detected format: {log_format}")

    print("\nSummary")
    print("-" * 68)
    for key, value in summary.items():
        if isinstance(value, list):
            if not value:
                continue
            print(f"  {key.replace('_', ' ')}:")
            for item, count in value[:5]:
                print(f"    {count:>8,}  {item}")
        elif isinstance(value, dict):
            rendered = ", ".join(f"{code}: {count:,}" for code, count in value.items())
            print(f"  {key.replace('_', ' ')}: {rendered}")
        elif value is not None:
            rendered = f"{value:,}" if isinstance(value, int) else str(value)
            print(f"  {key.replace('_', ' ')}: {rendered}")

    if unparsed:
        print(f"\n  {unparsed:,} line(s) did not match the expected format")

    print(f"\nFindings ({len(findings)})")
    print("-" * 68)
    if not findings:
        print("  Nothing stood out.")
        return

    for finding in findings:
        print(f"  [{finding.severity.upper()}] {finding.category}: {finding.summary}")
        for item in finding.evidence:
            print(f"      - {item}")
        print()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Parse authentication or web access logs and report anomalies",
    )
    parser.add_argument("logfile", help="Path to the log file, .gz is read directly")
    parser.add_argument(
        "--format",
        choices=("auto", "auth", "access"),
        default="auto",
        help="Log format, detected automatically by default",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=datetime.now().year,
        help="Year to assume for syslog timestamps, which omit it",
    )
    parser.add_argument("--failed-logins", type=int, default=5, help="Failures before reporting")
    parser.add_argument(
        "--not-found-burst", type=int, default=20, help="404s from one client before reporting"
    )
    parser.add_argument("--top", type=int, default=10, help="How many entries in each top list")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    parser.add_argument(
        "--fail-on-finding",
        action="store_true",
        help="Exit with code 1 when anything is reported, for use in a cron job",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    path = Path(args.logfile)
    if not path.is_file():
        print(f"[!] {path} is not a file.", file=sys.stderr)
        return 2

    thresholds = Thresholds(
        failed_logins=args.failed_logins,
        not_found_burst=args.not_found_burst,
        top_count=args.top,
    )

    try:
        lines = list(open_log(path))
    except OSError as exc:
        print(f"[!] Could not read {path}: {exc}", file=sys.stderr)
        return 2

    log_format = args.format
    if log_format == "auto":
        log_format = detect_format(lines)
        if log_format == "unknown":
            print(
                "[!] Could not detect the log format. Pass --format auth or --format access.",
                file=sys.stderr,
            )
            return 2

    findings, summary, unparsed = analyse(lines, log_format, thresholds, args.year)

    if args.json:
        print(
            json.dumps(
                {
                    "file": str(path),
                    "format": log_format,
                    "summary": summary,
                    "unparsed_lines": unparsed,
                    "findings": [
                        {
                            "severity": finding.severity,
                            "category": finding.category,
                            "summary": finding.summary,
                            "evidence": finding.evidence,
                        }
                        for finding in findings
                    ],
                },
                indent=2,
                default=str,
            )
        )
    else:
        print_report(path, log_format, findings, summary, unparsed)

    return 1 if findings and args.fail_on_finding else 0


if __name__ == "__main__":
    raise SystemExit(main())

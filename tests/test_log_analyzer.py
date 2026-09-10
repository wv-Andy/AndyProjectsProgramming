"""Tests for the log parser and anomaly reporter."""

from __future__ import annotations

import gzip
from pathlib import Path

import pytest

SAMPLES = Path(__file__).resolve().parent.parent / "Cybersecurity" / "log-analyzer" / "samples"


@pytest.fixture(scope="session")
def auth_lines():
    return (SAMPLES / "auth.log").read_text(encoding="utf-8").splitlines()


@pytest.fixture(scope="session")
def access_lines():
    return (SAMPLES / "access.log").read_text(encoding="utf-8").splitlines()


# --- Format detection and parsing -----------------------------------------


def test_detects_the_auth_format(log_analyzer, auth_lines):
    assert log_analyzer.detect_format(auth_lines) == "auth"


def test_detects_the_access_format(log_analyzer, access_lines):
    assert log_analyzer.detect_format(access_lines) == "access"


def test_unknown_format_is_reported(log_analyzer):
    assert log_analyzer.detect_format(["this is not a log line", "nor is this"]) == "unknown"


def test_parses_auth_failures_and_successes(log_analyzer, auth_lines):
    events, _ = log_analyzer.parse_auth_log(auth_lines, year=2026)
    assert any(event.success for event in events)
    assert any(not event.success for event in events)
    assert all(event.ip.count(".") == 3 for event in events)


def test_parses_an_invalid_user_line(log_analyzer):
    line = "Mar 15 09:03:17 host sshd[1]: Invalid user oracle from 203.0.113.42 port 40128"
    events, unparsed = log_analyzer.parse_auth_log([line], year=2026)
    assert unparsed == 0
    assert events[0].user == "oracle"
    assert events[0].ip == "203.0.113.42"
    assert events[0].success is False


def test_parses_a_pam_failure_line(log_analyzer):
    line = (
        "Mar 15 13:02:44 host sudo: pam_unix(sudo:auth): authentication failure; "
        "logname=andy uid=1000 euid=0 tty=/dev/pts/0 ruser=andy rhost=198.51.100.7 user=andy"
    )
    events, _ = log_analyzer.parse_auth_log([line], year=2026)
    assert events and events[0].ip == "198.51.100.7"


def test_parses_access_log_fields(log_analyzer, access_lines):
    events, _ = log_analyzer.parse_access_log(access_lines)
    first = events[0]
    assert first.ip == "192.168.1.50"
    assert first.method == "GET"
    assert first.status == 200
    assert first.size == 5120
    assert "Firefox" in first.agent


def test_counts_lines_it_cannot_parse(log_analyzer):
    _, unparsed = log_analyzer.parse_access_log(["not a log line at all"])
    assert unparsed == 1


def test_handles_a_dash_for_response_size(log_analyzer):
    line = '10.0.0.1 - - [15/Mar/2026:08:00:01 +0000] "GET / HTTP/1.1" 304 -'
    events, unparsed = log_analyzer.parse_access_log([line])
    assert unparsed == 0
    assert events[0].size == 0


def test_syslog_year_is_supplied_by_the_caller(log_analyzer, auth_lines):
    """Syslog omits the year, so it has to come from outside the line."""
    events, _ = log_analyzer.parse_auth_log(auth_lines, year=2019)
    stamped = [event for event in events if event.timestamp]
    assert stamped and all(event.timestamp.year == 2019 for event in stamped)


# --- Detection ------------------------------------------------------------


def test_finds_the_rapid_brute_force(log_analyzer, auth_lines):
    events, _ = log_analyzer.parse_auth_log(auth_lines, year=2026)
    findings = log_analyzer.find_brute_force(events, log_analyzer.Thresholds())
    high = [finding for finding in findings if finding.severity == "high"]
    assert any("203.0.113.42" in finding.summary for finding in high)


def test_a_slow_attack_is_lower_severity_than_a_fast_one(log_analyzer, auth_lines):
    """Twelve attempts in 22 seconds is automation. Six over three hours is not."""
    events, _ = log_analyzer.parse_auth_log(auth_lines, year=2026)
    findings = {
        finding.summary.split()[0]: finding
        for finding in log_analyzer.find_brute_force(events, log_analyzer.Thresholds())
    }
    assert findings["203.0.113.42"].severity == "high"
    assert findings["198.51.100.7"].severity == "medium"


def test_a_success_after_many_failures_is_critical(log_analyzer, auth_lines):
    events, _ = log_analyzer.parse_auth_log(auth_lines, year=2026)
    findings = log_analyzer.find_successful_logins_after_failures(
        events, log_analyzer.Thresholds()
    )
    assert findings
    assert findings[0].severity == "critical"
    assert "198.51.100.7" in findings[0].summary


def test_a_quiet_log_produces_nothing(log_analyzer):
    quiet = [
        "Mar 15 08:12:01 host sshd[1]: Accepted publickey for andy from 192.168.1.50 port 1 ssh2",
    ]
    events, _ = log_analyzer.parse_auth_log(quiet, year=2026)
    assert log_analyzer.find_brute_force(events, log_analyzer.Thresholds()) == []


def test_finds_the_path_scanner(log_analyzer, access_lines):
    events, _ = log_analyzer.parse_access_log(access_lines)
    findings = log_analyzer.find_scanning(events, log_analyzer.Thresholds())
    assert any("203.0.113.99" in finding.summary for finding in findings)


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/products?id=1%20UNION%20SELECT%20a,b%20FROM%20users", "SQL injection: UNION SELECT"),
        ("/products?id=1%27%20OR%20%271%27%3D%271", "SQL injection: OR 1=1"),
        ("/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "Cross-site scripting: script tag"),
        ("/download?file=../../../../etc/passwd", "Path traversal"),
        ("/ping?host=127.0.0.1%3B%20cat%20/etc/shadow", "Command injection"),
    ],
)
def test_injection_detection_decodes_the_path(log_analyzer, path, expected):
    """Attackers URL-encode payloads precisely to slip past substring matching."""
    event = log_analyzer.AccessEvent(
        timestamp=None, ip="10.0.0.1", method="GET", path=path, status=200, size=0, agent=""
    )
    findings = log_analyzer.find_injection_attempts([event])
    assert any(expected in finding.summary for finding in findings)


def test_double_encoding_is_still_caught(log_analyzer):
    event = log_analyzer.AccessEvent(
        timestamp=None,
        ip="10.0.0.1",
        method="GET",
        path="/products?id=1%2527%2520OR%25201%253D1",
        status=200,
        size=0,
        agent="",
    )
    assert log_analyzer.find_injection_attempts([event])


def test_a_normal_path_is_not_flagged(log_analyzer):
    event = log_analyzer.AccessEvent(
        timestamp=None,
        ip="10.0.0.1",
        method="GET",
        path="/products?id=42&sort=name",
        status=200,
        size=0,
        agent="Mozilla/5.0",
    )
    assert log_analyzer.find_injection_attempts([event]) == []


def test_finds_scanner_user_agents(log_analyzer, access_lines):
    events, _ = log_analyzer.parse_access_log(access_lines)
    findings = log_analyzer.find_scanner_agents(events)
    assert any("sqlmap" in finding.summary for finding in findings)


def test_error_rate_is_reported_above_the_threshold(log_analyzer, access_lines):
    events, _ = log_analyzer.parse_access_log(access_lines)
    findings = log_analyzer.find_error_rate(events, log_analyzer.Thresholds(error_rate_percent=5))
    assert findings and "availability" == findings[0].category


def test_error_rate_stays_quiet_below_the_threshold(log_analyzer, access_lines):
    events, _ = log_analyzer.parse_access_log(access_lines)
    findings = log_analyzer.find_error_rate(events, log_analyzer.Thresholds(error_rate_percent=99))
    assert findings == []


def test_error_rate_handles_an_empty_log(log_analyzer):
    assert log_analyzer.find_error_rate([], log_analyzer.Thresholds()) == []


# --- Reporting ------------------------------------------------------------


def test_findings_are_ordered_by_severity(log_analyzer, auth_lines):
    findings, _, _ = log_analyzer.analyse(auth_lines, "auth", log_analyzer.Thresholds(), 2026)
    order = [log_analyzer.SEVERITY_ORDER[finding.severity] for finding in findings]
    assert order == sorted(order)


def test_summary_counts_match_the_sample(log_analyzer, access_lines):
    _, summary, _ = log_analyzer.analyse(access_lines, "access", log_analyzer.Thresholds(), 2026)
    assert summary["requests"] == len(access_lines)
    assert summary["unique_clients"] == 6


def test_reads_a_gzipped_log(log_analyzer, tmp_path, access_lines):
    archive = tmp_path / "access.log.gz"
    with gzip.open(archive, "wt", encoding="utf-8") as handle:
        handle.write("\n".join(access_lines))
    assert len(list(log_analyzer.open_log(archive))) == len(access_lines)


def test_cli_rejects_a_missing_file(log_analyzer, tmp_path):
    assert log_analyzer.main([str(tmp_path / "nope.log")]) == 2


def test_cli_fail_on_finding_sets_the_exit_code(log_analyzer):
    path = str(SAMPLES / "auth.log")
    assert log_analyzer.main([path, "--json"]) == 0
    assert log_analyzer.main([path, "--json", "--fail-on-finding"]) == 1

"""Tests for the vulnerability matcher.

The version comparison and range logic are the heart of the tool, and every
false match or missed match is a real bug, so they are tested hard.
"""

from __future__ import annotations

from pathlib import Path

import pytest

FEED = Path(__file__).resolve().parent.parent / "Cybersecurity" / "vuln-scanner" / "feed.json"


# --- Version parsing and comparison ---------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("1.2.3", (1, 2, 3)),
        ("2.4.49", (2, 4, 49)),
        ("2.4.49p1", (2, 4, 49, 1)),
        ("7.4", (7, 4)),
        ("nonsense", (0,)),
    ],
)
def test_parse_version(vulndb, text, expected):
    assert vulndb.parse_version(text) == expected


@pytest.mark.parametrize(
    ("left", "right", "sign"),
    [
        ("1.2.3", "1.2.4", -1),
        ("1.2.4", "1.2.3", 1),
        ("1.2.3", "1.2.3", 0),
        ("1.2", "1.2.0", 0),
        ("2.4.49", "2.4.50", -1),
        ("1.10", "1.9", 1),
    ],
)
def test_compare_versions(vulndb, left, right, sign):
    assert vulndb.compare_versions(left, right) == sign


def test_compare_treats_1_10_above_1_9(vulndb):
    """String comparison would put 1.10 below 1.9. Numeric comparison must not."""
    assert vulndb.compare_versions("1.10.0", "1.9.0") == 1


# --- Range membership -----------------------------------------------------


def test_version_inside_an_inclusive_range(vulndb):
    assert vulndb.version_in_range(
        "2.4.49", "2.4.49", "2.4.50", start_inclusive=True, end_inclusive=True
    )


def test_version_at_an_exclusive_end_is_out(vulndb):
    assert not vulndb.version_in_range(
        "7.6", None, "7.6", start_inclusive=True, end_inclusive=False
    )


def test_version_below_the_end_is_in(vulndb):
    assert vulndb.version_in_range(
        "7.5", None, "7.6", start_inclusive=True, end_inclusive=False
    )


def test_version_below_the_start_is_out(vulndb):
    assert not vulndb.version_in_range(
        "2.4.48", "2.4.49", "2.4.50", start_inclusive=True, end_inclusive=True
    )


def test_open_ended_range(vulndb):
    assert vulndb.version_in_range("1.0", None, None, start_inclusive=True, end_inclusive=True)


# --- Feed loading ---------------------------------------------------------


def test_loads_the_bundled_feed(vulndb):
    feed = vulndb.load_feed(FEED)
    assert len(feed) >= 8
    assert all(entry.cve.startswith("CVE-") for entry in feed)


def test_feed_products_are_lowercased(vulndb):
    feed = vulndb.load_feed(FEED)
    assert all(entry.product == entry.product.lower() for entry in feed)


def test_load_rejects_a_missing_file(vulndb, tmp_path):
    with pytest.raises(vulndb.FeedError):
        vulndb.load_feed(tmp_path / "nope.json")


def test_load_rejects_a_non_list(vulndb, tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('{"not": "a list"}', encoding="utf-8")
    with pytest.raises(vulndb.FeedError):
        vulndb.load_feed(path)


def test_load_rejects_a_malformed_entry(vulndb, tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('[{"product": "apache"}]', encoding="utf-8")  # no cve
    with pytest.raises(vulndb.FeedError):
        vulndb.load_feed(path)


# --- Severity -------------------------------------------------------------


@pytest.mark.parametrize(
    ("cvss", "severity"),
    [(10.0, "critical"), (9.8, "critical"), (7.5, "high"), (5.3, "medium"), (2.0, "low")],
)
def test_severity_bands(vulndb, cvss, severity):
    vuln = vulndb.Vulnerability(
        cve="CVE-x", product="p", version_start=None, version_end=None,
        start_inclusive=True, end_inclusive=True, cvss=cvss, description="",
    )
    assert vuln.severity == severity


# --- Matching -------------------------------------------------------------


def test_matches_a_vulnerable_apache(vulndb):
    feed = vulndb.load_feed(FEED)
    service = vulndb.DetectedService(product="apache", version="2.4.49", port=80)
    matches = vulndb.match_service(service, feed)
    cves = {match.vulnerability.cve for match in matches}
    assert "CVE-2021-41773" in cves
    assert "CVE-2021-42013" in cves


def test_does_not_match_a_patched_apache(vulndb):
    feed = vulndb.load_feed(FEED)
    service = vulndb.DetectedService(product="apache", version="2.4.62", port=80)
    assert vulndb.match_service(service, feed) == []


def test_does_not_match_a_different_product(vulndb):
    feed = vulndb.load_feed(FEED)
    service = vulndb.DetectedService(product="nginx", version="2.4.49", port=80)
    # nginx 2.4.49 does not exist and must not pick up the Apache CVEs.
    cves = {m.vulnerability.cve for m in vulndb.match_service(service, feed)}
    assert "CVE-2021-41773" not in cves


def test_match_all_orders_by_severity(vulndb):
    feed = vulndb.load_feed(FEED)
    services = [
        vulndb.DetectedService(product="openssh", version="7.4", port=22),
        vulndb.DetectedService(product="vsftpd", version="2.3.4", port=21),
    ]
    matches = vulndb.match_all(services, feed)
    scores = [match.vulnerability.cvss for match in matches]
    assert scores == sorted(scores, reverse=True)
    assert matches[0].vulnerability.cve == "CVE-2011-2523"  # the vsftpd backdoor, CVSS 9.8


# --- Banner parsing -------------------------------------------------------


@pytest.mark.parametrize(
    ("banner", "product", "version"),
    [
        ("Apache/2.4.49 (Unix)", "apache", "2.4.49"),
        ("nginx/1.5.7", "nginx", "1.5.7"),
        ("SSH-2.0-OpenSSH_7.4", "openssh", "7.4"),
        ("220 (vsFTPd 2.3.4)", "vsftpd", "2.3.4"),
    ],
)
def test_parse_banner(vulndb, banner, product, version):
    detected = vulndb.parse_banner(banner, port=80)
    assert detected is not None
    assert detected.product == product
    assert detected.version == version


def test_parse_banner_returns_none_for_an_unknown_banner(vulndb):
    assert vulndb.parse_banner("some random text", port=80) is None


def test_end_to_end_banner_to_cve(vulndb):
    """A raw banner should flow through to a real CVE match."""
    feed = vulndb.load_feed(FEED)
    detected = vulndb.parse_banner("220 (vsFTPd 2.3.4)", port=21)
    matches = vulndb.match_service(detected, feed)
    assert any(m.vulnerability.cve == "CVE-2011-2523" for m in matches)

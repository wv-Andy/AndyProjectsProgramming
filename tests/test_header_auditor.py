"""Tests for the HTTP security header auditor."""

from __future__ import annotations

import pytest

STRONG_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=()",
}


def test_a_fully_configured_site_scores_full_marks(header_auditor):
    findings = header_auditor.audit_headers(STRONG_HEADERS, is_https=True)
    assert header_auditor.score(findings) == 100
    assert header_auditor.grade(100) == "A"


def test_a_site_with_no_headers_scores_zero(header_auditor):
    findings = header_auditor.audit_headers({}, is_https=True)
    assert header_auditor.score(findings) == 0
    assert header_auditor.grade(0) == "F"
    assert all(not finding.present for finding in findings)


def test_header_lookup_is_case_insensitive(header_auditor):
    headers = {"strict-transport-security": "max-age=31536000; includeSubDomains"}
    assert header_auditor.lookup(headers, "Strict-Transport-Security") is not None
    assert header_auditor.lookup(headers, "STRICT-TRANSPORT-SECURITY") is not None
    assert header_auditor.lookup(headers, "Missing-Header") is None


def test_a_weak_header_earns_partial_credit(header_auditor):
    """Present but weak still beats absent, and the report says what to fix."""
    weak = dict(STRONG_HEADERS, **{"X-Frame-Options": "ALLOW-FROM https://example.com"})
    findings = header_auditor.audit_headers(weak, is_https=True)
    frame = next(f for f in findings if f.header == "X-Frame-Options")
    assert frame.present is True
    assert frame.passed is False
    assert 0 < frame.earned < frame.weight


# --- Individual header rules ----------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("max-age=31536000; includeSubDomains", True),
        ("max-age=31536000", True),
        ("max-age=100", False),
        ("includeSubDomains", False),
        ("max-age=abc", False),
    ],
)
def test_hsts_rules(header_auditor, value, expected):
    passed, _ = header_auditor.check_hsts(value)
    assert passed is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("default-src 'self'", True),
        ("script-src 'self' https://cdn.example.com", True),
        ("default-src 'self' 'unsafe-inline'", False),
        ("default-src 'self' 'unsafe-inline' 'unsafe-eval'", False),
        ("upgrade-insecure-requests", False),
    ],
)
def test_csp_rules(header_auditor, value, expected):
    passed, _ = header_auditor.check_csp(value)
    assert passed is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [("DENY", True), ("SAMEORIGIN", True), ("sameorigin", True), ("ALLOW-FROM x", False)],
)
def test_frame_options_rules(header_auditor, value, expected):
    passed, _ = header_auditor.check_frame_options(value)
    assert passed is expected


@pytest.mark.parametrize(
    ("value", "expected"), [("nosniff", True), ("NOSNIFF", True), ("sniff", False)]
)
def test_content_type_options_rules(header_auditor, value, expected):
    passed, _ = header_auditor.check_content_type_options(value)
    assert passed is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("strict-origin-when-cross-origin", True),
        ("no-referrer", True),
        ("unsafe-url", False),
        ("no-referrer-when-downgrade", False),
    ],
)
def test_referrer_policy_rules(header_auditor, value, expected):
    passed, _ = header_auditor.check_referrer_policy(value)
    assert passed is expected


# --- Scheme, grading and disclosure ---------------------------------------


def test_hsts_over_plain_http_never_passes(header_auditor):
    """HSTS in an HTTP response is ignored by browsers, so it cannot count."""
    findings = header_auditor.audit_headers(STRONG_HEADERS, is_https=False)
    hsts = next(f for f in findings if f.header == "Strict-Transport-Security")
    assert hsts.passed is False
    assert hsts.earned == 0


@pytest.mark.parametrize(
    ("percentage", "letter"),
    [(100, "A"), (90, "A"), (89, "B"), (75, "C"), (65, "D"), (45, "E"), (10, "F")],
)
def test_grade_boundaries(header_auditor, percentage, letter):
    assert header_auditor.grade(percentage) == letter


def test_find_disclosures(header_auditor):
    headers = {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4", "Date": "now"}
    disclosures = dict(header_auditor.find_disclosures(headers))
    assert disclosures == {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4"}


def test_normalise_url_defaults_to_https(header_auditor):
    assert header_auditor.normalise_url("example.com") == "https://example.com"
    assert header_auditor.normalise_url("http://example.com") == "http://example.com"


def test_build_report_shape(header_auditor):
    findings = header_auditor.audit_headers(STRONG_HEADERS, is_https=True)
    report = header_auditor.build_report("https://example.com", 200, findings, [])
    assert report["grade"] == "A"
    assert report["score"] == 100
    assert len(report["checks"]) == len(header_auditor.CHECKS)


def test_rejects_an_invalid_fail_under(header_auditor):
    assert header_auditor.main(["example.com", "--fail-under", "150"]) == 2


def test_rejects_an_unsupported_scheme(header_auditor):
    with pytest.raises(header_auditor.AuditError):
        header_auditor.fetch_headers("ftp://example.com", timeout=1, insecure=False, follow=False)


@pytest.mark.network
def test_audits_a_live_site(header_auditor):
    try:
        headers, status, url = header_auditor.fetch_headers(
            "https://github.com", timeout=20, insecure=False, follow=True
        )
    except header_auditor.AuditError as exc:
        pytest.skip(f"Network unavailable: {exc}")

    assert status == 200
    findings = header_auditor.audit_headers(headers, is_https=True)
    # GitHub sets HSTS and nosniff, so a live audit should never score zero.
    assert header_auditor.score(findings) > 0

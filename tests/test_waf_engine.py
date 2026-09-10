"""Tests for the WAF inspection engine.

All offline: a Request is built, inspected, and its verdict checked. The rate
limiter is driven with an injected clock so it needs no real time.
"""

from __future__ import annotations

import pytest


def request(waf_engine, **kwargs):
    defaults = {"method": "GET", "path": "/", "query": "", "body": ""}
    defaults.update(kwargs)
    return waf_engine.Request(**defaults)


# --- Clean traffic --------------------------------------------------------


def test_a_normal_request_is_allowed(waf_engine):
    verdict = waf_engine.inspect(request(waf_engine, path="/products", query="id=42&sort=name"))
    assert verdict.allowed is True
    assert verdict.score == 0


def test_a_normal_post_is_allowed(waf_engine):
    verdict = waf_engine.inspect(
        request(waf_engine, method="POST", path="/login", body="user=andy&pass=secret")
    )
    assert verdict.allowed is True


# --- SQL injection --------------------------------------------------------


@pytest.mark.parametrize(
    "query",
    [
        "id=1 UNION SELECT username,password FROM users",
        "id=1' OR '1'='1",
        "id=1; DROP TABLE users",
        "id=1 AND sleep(5)",
    ],
)
def test_blocks_sql_injection(waf_engine, query):
    verdict = waf_engine.inspect(request(waf_engine, path="/products", query=query))
    assert verdict.allowed is False
    assert any(d.category == "sql-injection" for d in verdict.detections)


# --- XSS ------------------------------------------------------------------


@pytest.mark.parametrize(
    "query",
    [
        "q=<script>alert(1)</script>",
        "q=<img src=x onerror=alert(1)>",
        "next=javascript:alert(document.cookie)",
    ],
)
def test_blocks_xss(waf_engine, query):
    verdict = waf_engine.inspect(request(waf_engine, path="/search", query=query))
    assert verdict.allowed is False
    assert any(d.category == "xss" for d in verdict.detections)


# --- Path traversal and command injection ---------------------------------


def test_blocks_path_traversal(waf_engine):
    verdict = waf_engine.inspect(
        request(waf_engine, path="/download", query="file=../../../../etc/passwd")
    )
    assert verdict.allowed is False
    assert any(d.category == "path-traversal" for d in verdict.detections)


def test_blocks_command_injection(waf_engine):
    verdict = waf_engine.inspect(
        request(waf_engine, path="/ping", query="host=127.0.0.1; cat /etc/shadow")
    )
    assert verdict.allowed is False
    assert any(d.category == "command-injection" for d in verdict.detections)


# --- Encoding evasion -----------------------------------------------------


def test_blocks_url_encoded_payloads(waf_engine):
    """A payload encoded to slip past a naive filter must still be caught."""
    encoded = "id=1%20UNION%20SELECT%20a%2Cb%20FROM%20users"
    verdict = waf_engine.inspect(request(waf_engine, path="/products", query=encoded))
    assert verdict.allowed is False


def test_blocks_double_encoded_payloads(waf_engine):
    double = "q=%253Cscript%253Ealert(1)%253C/script%253E"
    verdict = waf_engine.inspect(request(waf_engine, path="/search", query=double))
    assert verdict.allowed is False


def test_inspects_headers_too(waf_engine):
    verdict = waf_engine.inspect(
        request(waf_engine, path="/", headers={"User-Agent": "sqlmap/1.8"})
    )
    assert any(d.category == "reconnaissance" for d in verdict.detections)


# --- Scoring --------------------------------------------------------------


def test_weak_signals_accumulate(waf_engine):
    """A single low-severity signature stays under the threshold."""
    verdict = waf_engine.inspect(request(waf_engine, path="/", query="c=`id`"), threshold=5)
    # A backtick alone scores 3, below the default threshold of 5.
    assert verdict.score == 3
    assert verdict.allowed is True


def test_threshold_is_configurable(waf_engine):
    req = request(waf_engine, path="/", query="c=`id`")
    assert waf_engine.inspect(req, threshold=3).allowed is False
    assert waf_engine.inspect(req, threshold=4).allowed is True


def test_verdict_lists_every_detection(waf_engine):
    verdict = waf_engine.inspect(
        request(waf_engine, path="/", query="a=<script>&b=1 UNION SELECT 1")
    )
    categories = {d.category for d in verdict.detections}
    assert "xss" in categories
    assert "sql-injection" in categories


# --- Rate limiter ---------------------------------------------------------


def test_rate_limiter_allows_up_to_the_limit(waf_engine):
    limiter = waf_engine.RateLimiter(max_requests=3, window_seconds=10)
    assert limiter.check("1.2.3.4", now=0) is True
    assert limiter.check("1.2.3.4", now=1) is True
    assert limiter.check("1.2.3.4", now=2) is True
    assert limiter.check("1.2.3.4", now=3) is False  # the fourth in the window


def test_rate_limiter_window_slides(waf_engine):
    limiter = waf_engine.RateLimiter(max_requests=2, window_seconds=10)
    assert limiter.check("1.2.3.4", now=0) is True
    assert limiter.check("1.2.3.4", now=1) is True
    assert limiter.check("1.2.3.4", now=2) is False
    # After the window passes, the early hits expire and requests are allowed.
    assert limiter.check("1.2.3.4", now=12) is True


def test_rate_limiter_is_per_client(waf_engine):
    limiter = waf_engine.RateLimiter(max_requests=1, window_seconds=10)
    assert limiter.check("1.1.1.1", now=0) is True
    assert limiter.check("2.2.2.2", now=0) is True  # different client, own budget
    assert limiter.check("1.1.1.1", now=1) is False


def test_rate_limiter_reset(waf_engine):
    limiter = waf_engine.RateLimiter(max_requests=1, window_seconds=10)
    limiter.check("1.1.1.1", now=0)
    limiter.reset("1.1.1.1")
    assert limiter.check("1.1.1.1", now=1) is True

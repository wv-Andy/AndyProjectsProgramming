"""Tests for the web scraper.

The link extraction and URL logic are offline and deterministic. A single
network test is marked and skips without connectivity.
"""

from __future__ import annotations

import asyncio

import pytest

SAMPLE_HTML = """
<html>
  <head><title>  Example Page  </title></head>
  <body>
    <a href="https://example.com/about">About</a>
    <a href="/contact">Contact</a>
    <a href="page2.html">Next</a>
    <a href="https://example.com/about">About again</a>
  </body>
</html>
"""


def test_extract_pulls_the_title(web_scraper):
    title, _ = web_scraper.extract(SAMPLE_HTML, "https://example.com/")
    assert title == "Example Page"


def test_extract_resolves_relative_links(web_scraper):
    _, links = web_scraper.extract(SAMPLE_HTML, "https://example.com/dir/")
    assert "https://example.com/contact" in links  # root-relative
    assert "https://example.com/dir/page2.html" in links  # path-relative


def test_extract_deduplicates_links(web_scraper):
    _, links = web_scraper.extract(SAMPLE_HTML, "https://example.com/")
    assert links.count("https://example.com/about") == 1


def test_extract_handles_no_title(web_scraper):
    title, links = web_scraper.extract("<a href='/x'>x</a>", "https://example.com/")
    assert title is None
    assert links == ["https://example.com/x"]


def test_same_host(web_scraper):
    assert web_scraper.same_host("https://a.com/1", "https://a.com/2") is True
    assert web_scraper.same_host("https://a.com/1", "https://b.com/2") is False


def test_fetch_rejects_unsupported_scheme(web_scraper):
    async def run():
        semaphore = asyncio.Semaphore(1)
        return await web_scraper.fetch(
            "ftp://example.com/file", timeout=1, semaphore=semaphore, delay=0
        )

    result = asyncio.run(run())
    assert result.ok is False
    assert result.error == "Unsupported scheme"


def test_fetch_reports_a_connection_error(web_scraper):
    async def run():
        semaphore = asyncio.Semaphore(1)
        return await web_scraper.fetch(
            "http://127.0.0.1:9/never", timeout=1, semaphore=semaphore, delay=0
        )

    result = asyncio.run(run())
    assert result.ok is False
    assert result.error is not None


def test_fetch_result_ok_property(web_scraper):
    ok = web_scraper.FetchResult(url="u", status=200)
    not_ok = web_scraper.FetchResult(url="u", status=404)
    errored = web_scraper.FetchResult(url="u", status=None, error="boom")
    assert ok.ok is True
    assert not_ok.ok is False
    assert errored.ok is False


def test_cli_rejects_bad_arguments(web_scraper):
    assert web_scraper.main(["http://example.com", "--concurrency", "0"]) == 2
    assert web_scraper.main(["http://example.com", "--max-pages", "0"]) == 2


@pytest.mark.network
def test_scrapes_a_real_page(web_scraper):
    async def run():
        return await web_scraper.scrape(
            ["https://example.com"], concurrency=1, timeout=15, delay=0
        )

    try:
        results = asyncio.run(run())
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Network unavailable: {exc}")

    if not results[0].ok:
        pytest.skip(f"Could not reach example.com: {results[0].error}")
    assert results[0].title is not None

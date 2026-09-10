"""A concurrent, polite web scraper.

Fetches many URLs at once with asyncio, but stays polite: a concurrency cap, a
per-request delay, a timeout, and it reads robots.txt before crawling a host.
The HTML link extraction is a standard-library HTMLParser, so there are no
dependencies.

This reuses the asyncio patterns from the port scanner in a completely different
domain, which is the point: concurrency is a tool, not a networking trick.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen
from urllib.robotparser import RobotFileParser

USER_AGENT = "polite-scraper/1.0"


@dataclass
class FetchResult:
    url: str
    status: int | None
    title: str | None = None
    links: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status == 200


class LinkExtractor(HTMLParser):
    """Pull the page title and every href out of an HTML document."""

    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.links: list[str] = []
        self.title: str | None = None
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "title":
            self._in_title = True
        elif tag == "a":
            for name, value in attrs:
                if name == "href" and value:
                    # Resolve relative links against the page they came from.
                    self.links.append(urljoin(self.base_url, value))

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and self.title is None:
            stripped = data.strip()
            if stripped:
                self.title = stripped


def extract(html: str, base_url: str) -> tuple[str | None, list[str]]:
    parser = LinkExtractor(base_url)
    parser.feed(html)
    # De-duplicate while preserving order.
    seen: set[str] = set()
    unique = [link for link in parser.links if not (link in seen or seen.add(link))]
    return parser.title, unique


def same_host(a: str, b: str) -> bool:
    return urlparse(a).netloc == urlparse(b).netloc


def _blocking_fetch(url: str, timeout: float) -> tuple[int, str]:
    """The blocking HTTP call, run off the event loop in a thread."""
    request = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(request, timeout=timeout) as response:  # noqa: S310 - http(s) only, checked below
        charset = response.headers.get_content_charset() or "utf-8"
        body = response.read(2_000_000).decode(charset, errors="replace")
        return response.status, body


async def fetch(
    url: str,
    *,
    timeout: float,
    semaphore: asyncio.Semaphore,
    delay: float,
) -> FetchResult:
    """Fetch one URL, respecting the concurrency cap and the politeness delay."""
    if urlparse(url).scheme not in ("http", "https"):
        return FetchResult(url=url, status=None, error="Unsupported scheme")

    async with semaphore:
        loop = asyncio.get_running_loop()
        try:
            status, body = await loop.run_in_executor(None, _blocking_fetch, url, timeout)
        except Exception as exc:  # urlopen raises a wide range of errors
            return FetchResult(url=url, status=None, error=str(exc))
        finally:
            # Wait after releasing nobody: the delay throttles this worker before
            # it picks up the next URL, which is what keeps the crawl polite.
            if delay > 0:
                await asyncio.sleep(delay)

        title, links = extract(body, url)
        return FetchResult(url=url, status=status, title=title, links=links)


async def scrape(
    urls: Iterable[str],
    *,
    concurrency: int,
    timeout: float,
    delay: float,
) -> list[FetchResult]:
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [
        fetch(url, timeout=timeout, semaphore=semaphore, delay=delay) for url in urls
    ]
    return await asyncio.gather(*tasks)


def load_robots(start_url: str, timeout: float) -> RobotFileParser:
    """Fetch and parse robots.txt for the start URL's host."""
    parsed = urlparse(start_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    parser = RobotFileParser()
    parser.set_url(robots_url)
    try:
        request = Request(robots_url, headers={"User-Agent": USER_AGENT})
        with urlopen(request, timeout=timeout) as response:  # noqa: S310
            parser.parse(response.read().decode("utf-8", errors="replace").splitlines())
    except Exception:
        # No robots.txt means nothing is disallowed.
        parser.parse([])
    return parser


async def crawl(
    start_url: str,
    *,
    max_pages: int,
    concurrency: int,
    timeout: float,
    delay: float,
    obey_robots: bool,
) -> list[FetchResult]:
    """Breadth-first crawl within one host, up to max_pages."""
    robots = load_robots(start_url, timeout) if obey_robots else None

    seen: set[str] = {start_url}
    queue: list[str] = [start_url]
    results: list[FetchResult] = []

    while queue and len(results) < max_pages:
        batch = queue[:concurrency]
        queue = queue[concurrency:]

        if robots is not None:
            batch = [url for url in batch if robots.can_fetch(USER_AGENT, url)]
        if not batch:
            continue

        fetched = await scrape(batch, concurrency=concurrency, timeout=timeout, delay=delay)
        for result in fetched:
            results.append(result)
            if len(results) >= max_pages:
                break
            for link in result.links:
                if link not in seen and same_host(link, start_url):
                    seen.add(link)
                    queue.append(link)

    return results


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="A concurrent, polite web scraper",
        epilog="Respect robots.txt and only scrape sites that permit it.",
    )
    parser.add_argument("url", help="Start URL")
    parser.add_argument("--max-pages", type=int, default=10, help="Maximum pages to crawl")
    parser.add_argument("--concurrency", type=int, default=5, help="Simultaneous requests")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout")
    parser.add_argument(
        "--delay", type=float, default=0.5, help="Delay per worker between requests"
    )
    parser.add_argument(
        "--ignore-robots", action="store_true", help="Do not read or obey robots.txt"
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    if args.concurrency < 1 or args.max_pages < 1 or args.timeout <= 0:
        print("[!] concurrency and max-pages must be >= 1, timeout > 0.", file=sys.stderr)
        return 2

    started = time.perf_counter()
    results = asyncio.run(
        crawl(
            args.url,
            max_pages=args.max_pages,
            concurrency=args.concurrency,
            timeout=args.timeout,
            delay=args.delay,
            obey_robots=not args.ignore_robots,
        )
    )
    duration = time.perf_counter() - started

    ok = [result for result in results if result.ok]
    print(f"\nCrawled {len(results)} page(s), {len(ok)} successful, in {duration:.1f}s\n")
    for result in results:
        if result.ok:
            print(f"  200  {result.title or '(no title)'}")
            print(f"       {result.url}  ({len(result.links)} links)")
        else:
            print(f"  ---  {result.url}  [{result.error or result.status}]")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

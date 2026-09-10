# Concurrent Web Scraper

Crawls a website concurrently while staying polite. No dependencies; link
extraction uses the standard library's HTML parser.

This reuses the `asyncio` patterns from the [port
scanner](../../Cybersecurity/async-port-scanner/) in a completely different
domain, which is the point: concurrency is a general tool, not a networking
trick.

## Usage

```bash
# Crawl up to 10 pages of a site
python scraper.py https://example.com

# More pages, more workers, a gentler delay
python scraper.py https://example.com --max-pages 50 --concurrency 10 --delay 1.0
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--max-pages` | `10` | Maximum pages to crawl |
| `--concurrency` | `5` | Simultaneous requests |
| `--timeout` | `10.0` | Per-request timeout |
| `--delay` | `0.5` | Delay per worker between requests |
| `--ignore-robots` | off | Skip the robots.txt check |

## Politeness is the point

A scraper that hammers a site as fast as it can is a denial-of-service tool by
accident. This one is deliberately restrained:

- **A concurrency cap** limits how many requests are ever in flight at once.
- **A per-worker delay** spaces out requests, so throughput stays civil even
  with several workers.
- **A timeout** stops one slow page from stalling the whole crawl.
- **robots.txt is read and obeyed** before crawling a host, using the standard
  library's `RobotFileParser`. A site that asks not to be crawled is not crawled.

## How the concurrency works

Blocking HTTP calls run in a thread-pool executor, so the event loop stays free
while a request is in flight. A semaphore caps how many run at once. The crawl
itself is breadth-first: fetch a batch, collect the links that point to the same
host and have not been seen, queue them, repeat until the page limit is reached.

## What I learned

- `asyncio` applied outside networking, and `run_in_executor` for blocking calls
- Why a scraper must rate-limit itself, and how a semaphore plus a delay does it
- Reading and obeying robots.txt with the standard library
- Resolving relative links against their page, and deduplicating a frontier

## Disclaimer

Only scrape sites that permit it. Respect robots.txt and the site's terms.

## License

MIT, see [LICENSE](../../LICENSE).

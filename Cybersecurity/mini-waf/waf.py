"""A minimal web application firewall, running as a reverse proxy.

Requests arrive here, are inspected by `engine`, and are either forwarded to the
backend or blocked with a 403. Every decision is logged. This is the thin
network shell; all the judgement lives in the engine, which is why the tests
never open a socket.
"""

from __future__ import annotations

import argparse
import http.client
import json
import sys
import time
from collections.abc import Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

from engine import DEFAULT_THRESHOLD, RateLimiter, Request, inspect  # noqa: E402

MAX_BODY = 1 << 20  # 1 MiB, enough for normal requests and a cap on abuse


class Stats:
    def __init__(self) -> None:
        self.allowed = 0
        self.blocked = 0
        self.rate_limited = 0


def make_handler(
    backend: str,
    *,
    threshold: int,
    limiter: RateLimiter,
    stats: Stats,
    log,
):
    backend_parts = urlsplit(backend)
    backend_host = backend_parts.hostname or "127.0.0.1"
    backend_port = backend_parts.port or 80

    class WAFHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args) -> None:  # silence the default logger
            pass

        def _client_ip(self) -> str:
            return self.client_address[0]

        def _read_body(self) -> str:
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length <= 0:
                return ""
            raw = self.rfile.read(min(length, MAX_BODY))
            return raw.decode("utf-8", errors="replace")

        def _handle(self) -> None:
            client_ip = self._client_ip()

            if not limiter.check(client_ip):
                stats.rate_limited += 1
                log(
                    {
                        "event": "rate-limited",
                        "client": client_ip,
                        "path": self.path,
                        "time": time.time(),
                    }
                )
                self._respond(429, "Too Many Requests")
                return

            split = urlsplit(self.path)
            body = self._read_body()
            request = Request(
                method=self.command,
                path=split.path,
                query=split.query,
                headers=dict(self.headers.items()),
                body=body,
                client_ip=client_ip,
            )

            verdict = inspect(request, threshold=threshold)
            if not verdict.allowed:
                stats.blocked += 1
                log(
                    {
                        "event": "blocked",
                        "client": client_ip,
                        "method": request.method,
                        "path": self.path,
                        "score": verdict.score,
                        "categories": sorted({d.category for d in verdict.detections}),
                        "time": time.time(),
                    }
                )
                self._respond(403, "Forbidden: request blocked by WAF")
                return

            stats.allowed += 1
            self._forward(request, body)

        def _forward(self, request: Request, body: str) -> None:
            try:
                connection = http.client.HTTPConnection(
                    backend_host, backend_port, timeout=10
                )
                headers = dict(request.headers)
                headers.pop("Host", None)
                connection.request(
                    self.command, self.path, body=body.encode() or None, headers=headers
                )
                response = connection.getresponse()
                payload = response.read()
                self.send_response(response.status)
                for key, value in response.getheaders():
                    if key.lower() in ("transfer-encoding", "connection", "content-length"):
                        continue
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                connection.close()
            except OSError as exc:
                self._respond(502, f"Bad Gateway: {exc}")

        def _respond(self, status: int, message: str) -> None:
            payload = message.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = _handle
        do_POST = _handle
        do_PUT = _handle
        do_DELETE = _handle
        do_HEAD = _handle

    return WAFHandler


def make_logger(path: Path | None):
    def log(entry: dict) -> None:
        line = json.dumps(entry)
        if path is not None:
            with path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        else:
            print(line)

    return log


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="A minimal web application firewall reverse proxy",
    )
    parser.add_argument("--listen", default="127.0.0.1:8080", help="Address to listen on")
    parser.add_argument(
        "--backend", default="http://127.0.0.1:8000", help="Backend to forward clean requests to"
    )
    parser.add_argument(
        "--threshold", type=int, default=DEFAULT_THRESHOLD, help="Score at which to block"
    )
    parser.add_argument("--rate", type=int, default=100, help="Max requests per client per window")
    parser.add_argument("--window", type=float, default=10.0, help="Rate-limit window in seconds")
    parser.add_argument("--log", type=Path, help="Append JSON decisions to this file")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    listen = urlsplit(f"//{args.listen}")
    host = listen.hostname or "127.0.0.1"
    port = listen.port or 8080

    if args.threshold < 1 or args.rate < 1 or args.window <= 0:
        print("[!] threshold and rate must be >= 1, and window > 0.", file=sys.stderr)
        return 2

    limiter = RateLimiter(args.rate, args.window)
    stats = Stats()
    log = make_logger(args.log)
    handler = make_handler(
        args.backend, threshold=args.threshold, limiter=limiter, stats=stats, log=log
    )

    server = ThreadingHTTPServer((host, port), handler)
    print(f"WAF listening on {host}:{port}, forwarding clean traffic to {args.backend}")
    print(
        f"Blocking at score {args.threshold}, "
        f"rate limit {args.rate}/{args.window}s. Ctrl+C to stop."
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(
            f"\nStopped. Allowed {stats.allowed}, blocked {stats.blocked}, "
            f"rate-limited {stats.rate_limited}."
        )
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

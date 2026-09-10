"""Asynchronous TCP port scanner with service detection and banner grabbing.

Built for a learning portfolio: it leans on asyncio for speed, keeps every
platform-specific lookup behind a guard, and emits both a readable summary and
an optional JSON report.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import socket
import sys
import time
from collections.abc import Iterator, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

OPEN_STATUS = "open"
CLOSED_STATUS = "closed"
FILTERED_STATUS = "filtered"

MAX_PORT = 65535
BANNER_BYTES = 256

# Ports whose protocol the scanner knows how to nudge, independently of what
# the operating system services database happens to list.
HTTP_PORTS = {80, 81, 591, 8000, 8008, 8080, 8081, 8888}
TLS_PORTS = {443, 465, 636, 993, 995, 8443, 9443}
GREETING_PORTS = {21, 22, 23, 25, 110, 143, 587, 3389}

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
]

BOX_CHARS = "╔╗╚╝═║"


class PortSpecError(ValueError):
    """Raised when a ``--ports`` specification cannot be parsed."""


@dataclass
class PortScanResult:
    port: int
    status: str
    service: str | None = None
    banner: str | None = None


def lookup_service(port: int) -> str | None:
    """Resolve a port to its service name, or ``None`` when it is unknown.

    ``socket.getservbyport`` raises ``OSError`` for any port the platform
    services database does not list, so every caller goes through here. An
    unguarded call used to abort the probe and mislabel open ports as closed.
    """
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return None


def _parse_port(text: str, token: str) -> int:
    try:
        port = int(text.strip())
    except ValueError:
        raise PortSpecError(f"{token!r} is not a valid port or range.") from None
    if not 0 < port <= MAX_PORT:
        raise PortSpecError(f"Port {port} in {token!r} is outside 1-{MAX_PORT}.")
    return port


def _expand_token(token: str) -> Iterator[int]:
    if "-" in token:
        start_text, _, end_text = token.partition("-")
        start = _parse_port(start_text, token)
        end = _parse_port(end_text, token)
        if start > end:
            raise PortSpecError(
                f"Range {token!r} is reversed: {start} is greater than {end}."
            )
        return iter(range(start, end + 1))
    return iter((_parse_port(token, token),))


def parse_port_spec(spec: str) -> list[int]:
    """Expand a specification like ``22,80,8000-8100`` into a sorted port list."""
    ports: set[int] = set()
    for raw_token in spec.split(","):
        token = raw_token.strip()
        if not token:
            continue
        ports.update(_expand_token(token))
    return sorted(ports)


def build_probe(host: str, port: int, service: str | None) -> bytes | None:
    """Return the bytes to send to coax a banner out of a service."""
    if port in TLS_PORTS:
        # A plaintext probe gets nothing useful out of a TLS listener.
        return None
    if port in HTTP_PORTS or (service and "http" in service):
        return (
            "HEAD / HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            "User-Agent: async-port-scanner/1.0\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
    if port in GREETING_PORTS or service in {"smtp", "pop3", "imap", "ftp", "ssh"}:
        return b"\r\n"
    return None


def clean_banner(raw: bytes) -> str | None:
    """Collapse a raw banner into a single printable line."""
    text = raw.decode("utf-8", errors="replace")
    first_line = next((line.strip() for line in text.splitlines() if line.strip()), "")
    printable = "".join(char for char in first_line if char.isprintable())
    return printable or None


async def grab_banner(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str,
    port: int,
    service: str | None,
    timeout: float,
) -> str | None:
    """Attempt a small banner grab. Never raises: a failure just means no banner."""
    probe = build_probe(host, port, service)
    if probe is not None:
        try:
            writer.write(probe)
            await asyncio.wait_for(writer.drain(), timeout=timeout)
        except (asyncio.TimeoutError, OSError):
            return None

    try:
        raw = await asyncio.wait_for(reader.read(BANNER_BYTES), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return None

    return clean_banner(raw)


async def probe_port(
    host: str,
    port: int,
    *,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> PortScanResult:
    """Classify a single TCP port as open, closed or filtered."""
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
        except asyncio.TimeoutError:
            return PortScanResult(port=port, status=FILTERED_STATUS)
        except (ConnectionRefusedError, OSError):
            return PortScanResult(port=port, status=CLOSED_STATUS)

        # The connection succeeded, so the port is open no matter what the
        # banner grab does next.
        service = lookup_service(port)
        try:
            banner = await grab_banner(reader, writer, host, port, service, timeout)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (asyncio.TimeoutError, OSError):
                pass

        return PortScanResult(
            port=port, status=OPEN_STATUS, service=service, banner=banner
        )


async def run_scan(
    host: str,
    ports: Sequence[int],
    *,
    timeout: float,
    concurrency: int,
) -> list[PortScanResult]:
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [probe_port(host, port, timeout=timeout, semaphore=semaphore) for port in ports]
    results = await asyncio.gather(*tasks)
    return sorted(results, key=lambda result: result.port)


def resolve_host(host: str) -> str:
    """Resolve a target up front so a typo fails loudly instead of as 'closed'."""
    try:
        info = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise PortSpecError(f"Could not resolve {host!r}: {exc.strerror or exc}") from None
    return info[0][4][0]


def enable_unicode_output() -> None:
    """Ask stdout/stderr for UTF-8 so redirected output does not crash on Windows."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass


def supports_unicode(stream: object) -> bool:
    """Report whether a stream can encode the box-drawing header."""
    encoding = getattr(stream, "encoding", None) or "ascii"
    try:
        BOX_CHARS.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def pretty_header(host: str, resolved: str, *, unicode_ok: bool = True) -> str:
    title = f" Async Port Scanner | Target: {host}"
    if resolved != host:
        title += f" ({resolved})"
    width = max(len(title) + 1, 50)
    if not unicode_ok:
        ruler = "=" * width
        return f"\n+{ruler}\n|{title}\n+{ruler}"
    ruler = "═" * width
    return f"\n╔{ruler}\n║{title}\n╚{ruler}"


def format_result(result: PortScanResult) -> str:
    status = result.status.upper().ljust(9)
    service = result.service or "unknown"
    line = f"{status} {result.port:<5d} {service}"
    if result.banner:
        line += f" | {result.banner}"
    return line


def summarise(results: Sequence[PortScanResult]) -> dict[str, int]:
    counts = {OPEN_STATUS: 0, CLOSED_STATUS: 0, FILTERED_STATUS: 0}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    return counts


def build_report(
    host: str,
    resolved: str,
    results: Sequence[PortScanResult],
    *,
    duration: float,
    include_closed: bool,
) -> dict:
    kept = [
        result
        for result in results
        if include_closed or result.status != CLOSED_STATUS
    ]
    return {
        "target": host,
        "resolved_ip": resolved,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ports_scanned": len(results),
        "duration_seconds": round(duration, 2),
        "summary": summarise(results),
        "results": [asdict(result) for result in kept],
    }


def build_port_list(args: argparse.Namespace) -> list[int]:
    if args.ports:
        return parse_port_spec(args.ports)
    if args.top:
        return sorted(TOP_PORTS)
    if args.start_port > args.end_port:
        raise PortSpecError(
            f"--start-port {args.start_port} is greater than --end-port {args.end_port}."
        )
    return list(range(args.start_port, args.end_port + 1))


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Asynchronous TCP port scanner with banner grabbing",
        epilog="Only scan hosts you own or are explicitly authorised to test.",
    )
    parser.add_argument("host", help="Target host or IP address")
    parser.add_argument("--ports", help="Port list or ranges (e.g. 22,80,8000-8100)")
    parser.add_argument(
        "--start-port", type=int, default=1, help="Range start when --ports is omitted"
    )
    parser.add_argument(
        "--end-port", type=int, default=1024, help="Range end when --ports is omitted"
    )
    parser.add_argument(
        "--timeout", type=float, default=1.5, help="Timeout per port, in seconds"
    )
    parser.add_argument(
        "--concurrency", type=int, default=200, help="Simultaneous connection attempts"
    )
    parser.add_argument(
        "--top", action="store_true", help="Scan a curated list of common ports"
    )
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="Print closed ports too, instead of only open and filtered ones",
    )
    parser.add_argument("--json", dest="json_output", help="Write a JSON report to this path")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    enable_unicode_output()

    if args.concurrency < 1:
        print("[!] --concurrency must be at least 1.", file=sys.stderr)
        return 2
    if args.timeout <= 0:
        print("[!] --timeout must be greater than 0.", file=sys.stderr)
        return 2

    try:
        ports = build_port_list(args)
        resolved = resolve_host(args.host)
    except PortSpecError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    if not ports:
        print("[!] No ports to scan. Check --ports or the range arguments.", file=sys.stderr)
        return 2

    print(pretty_header(args.host, resolved, unicode_ok=supports_unicode(sys.stdout)))
    print(
        f"Scanning {len(ports)} ports with concurrency={args.concurrency} "
        f"and timeout={args.timeout}s\n"
    )

    started = time.perf_counter()
    results = asyncio.run(
        run_scan(args.host, ports, timeout=args.timeout, concurrency=args.concurrency)
    )
    duration = time.perf_counter() - started

    shown = [
        result
        for result in results
        if args.show_all or result.status != CLOSED_STATUS
    ]
    for result in shown:
        print(format_result(result))
    if not shown:
        print("No open or filtered ports found.")

    counts = summarise(results)
    print(
        f"\nOpen: {counts[OPEN_STATUS]}  "
        f"Filtered: {counts[FILTERED_STATUS]}  "
        f"Closed: {counts[CLOSED_STATUS]}  "
        f"({duration:.2f}s)"
    )

    if args.json_output:
        report = build_report(
            args.host, resolved, results, duration=duration, include_closed=args.show_all
        )
        with open(args.json_output, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
        print(f"Saved JSON report to {args.json_output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

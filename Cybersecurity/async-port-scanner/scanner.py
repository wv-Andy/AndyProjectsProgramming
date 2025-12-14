"""Asynchronous port scanner with smart banner grabbing.

This tool was created for a GitHub portfolio: it leans on asyncio for speed,
includes service heuristics, and emits a clean summary for quick sharing.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import socket
from dataclasses import dataclass, asdict
from typing import Iterable, List, Sequence, Tuple

OPEN_STATUS = "open"
CLOSED_STATUS = "closed"
FILTERED_STATUS = "filtered"

def parse_port_spec(spec: str) -> List[int]:
    """Expand a port specification like "22,80,8000-8100" into a list of ints."""

    def expand_token(token: str) -> Iterable[int]:
        if "-" in token:
            start, end = token.split("-", maxsplit=1)
            return range(int(start), int(end) + 1)
        return (int(token),)

    ports: List[int] = []
    for raw_token in spec.split(","):
        token = raw_token.strip()
        if not token:
            continue
        ports.extend(expand_token(token))
    return sorted(set(port for port in ports if 0 < port < 65536))


@dataclass
class PortScanResult:
    port: int
    status: str
    service: str | None = None
    banner: str | None = None


async def grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int, timeout: float) -> str | None:
    """Attempt a tiny banner grab depending on the detected service."""
    service_name = socket.getservbyport(port, "tcp") if port < 1024 else None
    probe = None

    if service_name and "http" in service_name:
        probe = b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"
    elif service_name in {"smtp", "pop3", "imap"}:
        probe = b"\r\n"
    elif port in {22, 23, 3389}:
        probe = b"\r\n"

    if probe:
        try:
            writer.write(probe)
            await writer.drain()
        except (ConnectionError, asyncio.TimeoutError):
            return None

    try:
        raw = await asyncio.wait_for(reader.read(256), timeout=timeout)
    except (asyncio.TimeoutError, ConnectionResetError, OSError):
        return None

    banner = raw.decode(errors="ignore").strip()
    return banner or None


async def probe_port(host: str, port: int, *, timeout: float, semaphore: asyncio.Semaphore) -> PortScanResult:
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            banner = await grab_banner(reader, writer, port, timeout)
            writer.close()
            await writer.wait_closed()
            service = None
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = None
            return PortScanResult(port=port, status=OPEN_STATUS, service=service, banner=banner)
        except asyncio.TimeoutError:
            return PortScanResult(port=port, status=FILTERED_STATUS)
        except (ConnectionRefusedError, OSError):
            return PortScanResult(port=port, status=CLOSED_STATUS)


def build_port_list(args: argparse.Namespace) -> List[int]:
    if args.ports:
        return parse_port_spec(args.ports)
    if args.top:
        return [80, 443, 22, 3389, 21, 23, 25, 53, 110, 143, 465, 587, 993, 995, 8080, 8443]
    return list(range(args.start_port, args.end_port + 1))


def format_result(result: PortScanResult) -> str:
    status = result.status.upper().ljust(9)
    service = result.service or "unknown"
    line = f"{status} {result.port:<5d} {service}"
    if result.banner:
        line += f" | {result.banner}"
    return line


def pretty_header(host: str) -> str:
    ruler = "═" * 48
    return f"\n╔{ruler}\n║ Async Port Scanner | Target: {host}\n╚{ruler}"


async def run_scan(host: str, ports: Sequence[int], *, timeout: float, concurrency: int) -> List[PortScanResult]:
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [probe_port(host, port, timeout=timeout, semaphore=semaphore) for port in ports]
    results = await asyncio.gather(*tasks)
    return sorted(results, key=lambda r: r.port)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Asynchronous port scanner with smart banners")
    parser.add_argument("host", help="Target host or IP address")
    parser.add_argument("--ports", help="Port list or ranges (e.g., 22,80,8000-8100)")
    parser.add_argument("--start-port", type=int, default=1, help="Start of range if --ports is not provided")
    parser.add_argument("--end-port", type=int, default=1024, help="End of range if --ports is not provided")
    parser.add_argument("--timeout", type=float, default=1.5, help="Timeout per port in seconds")
    parser.add_argument("--concurrency", type=int, default=200, help="Simultaneous connection attempts")
    parser.add_argument("--top", action="store_true", help="Scan a curated list of common ports")
    parser.add_argument("--json", dest="json_output", help="Write results to a JSON file")
    return parser.parse_args(argv)


def write_json(results: Sequence[PortScanResult], path: str) -> None:
    payload = [asdict(result) for result in results if result.status == OPEN_STATUS]
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    ports = build_port_list(args)
    if not ports:
        raise SystemExit("No valid ports to scan. Check your --ports or range arguments.")

    print(pretty_header(args.host))
    print(f"Scanning {len(ports)} ports with concurrency={args.concurrency} and timeout={args.timeout}s\n")

    results = asyncio.run(run_scan(args.host, ports, timeout=args.timeout, concurrency=args.concurrency))

    open_ports = [result for result in results if result.status == OPEN_STATUS]
    for result in results:
        print(format_result(result))

    print(f"\nOpen ports: {len(open_ports)}")
    if args.json_output:
        write_json(results, args.json_output)
        print(f"Saved JSON report to {args.json_output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
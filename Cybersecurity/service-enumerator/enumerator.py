"""Minimal HTTP/HTTPS service enumerator.

Sends a single HEAD request and reports the status line plus the headers that
tend to reveal the software behind a service.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import ssl
import sys
from collections.abc import Sequence

USER_AGENT = "service-enumerator/1.0"
READ_LIMIT = 64 * 1024
CHUNK_SIZE = 4096

# Ports that speak TLS by default when --tls / --no-tls is not given.
DEFAULT_TLS_PORTS = {443, 465, 636, 993, 995, 8443, 9443}

INTERESTING_HEADERS = (
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "Via",
    "Location",
    "Set-Cookie",
    "Strict-Transport-Security",
    "Content-Type",
    "Date",
)


class EnumerationError(RuntimeError):
    """Raised when a target cannot be reached or spoken to."""


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def build_request(host_header: str) -> bytes:
    return (
        "HEAD / HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    ).encode()


def read_response(sock: socket.socket, limit: int = READ_LIMIT) -> bytes:
    """Read until the header terminator, the peer closes, or the limit is hit.

    A single ``recv`` call can return a partial header block, so this loops.
    """
    buffer = bytearray()
    while len(buffer) < limit:
        try:
            chunk = sock.recv(CHUNK_SIZE)
        except TimeoutError:
            break
        if not chunk:
            break
        buffer.extend(chunk)
        if b"\r\n\r\n" in buffer:
            break
    return bytes(buffer)


def build_tls_context(insecure: bool) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def fetch(
    host: str,
    port: int,
    *,
    use_tls: bool,
    timeout: float,
    insecure: bool,
    server_name: str | None,
) -> str:
    """Send one HEAD request and return the raw response text."""
    host_header = server_name or host
    if port not in (80, 443):
        host_header = f"{host_header}:{port}"
    request = build_request(host_header)

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            if not use_tls:
                sock.sendall(request)
                raw = read_response(sock)
                return raw.decode("utf-8", errors="replace")

            context = build_tls_context(insecure)
            # SNI must be a hostname. Sending a bare IP is invalid, so drop it
            # and rely on --insecure, which is what raw-IP recon needs anyway.
            sni = server_name or (None if is_ip_literal(host) else host)
            if sni is None and not insecure:
                raise EnumerationError(
                    "TLS against a raw IP cannot verify a certificate. "
                    "Pass --insecure, or --server-name to set the expected hostname."
                )
            try:
                with context.wrap_socket(sock, server_hostname=sni) as tls_sock:
                    tls_sock.sendall(request)
                    raw = read_response(tls_sock)
                    return raw.decode("utf-8", errors="replace")
            except ssl.SSLError as exc:
                hint = ""
                if sni is None:
                    # Shared hosting and most CDNs refuse a handshake that
                    # carries no SNI, even with verification switched off.
                    hint = " The server may require SNI: retry with --server-name."
                raise EnumerationError(f"TLS handshake failed: {exc}.{hint}") from exc
    except EnumerationError:
        raise
    except OSError as exc:
        raise EnumerationError(f"Connection failed: {exc}") from exc


def parse_status_line(raw: str) -> str | None:
    lines = raw.splitlines()
    if not lines or not lines[0].strip():
        return None
    return lines[0].strip()


def parse_headers(raw: str) -> dict[str, str]:
    """Parse the header block, folding repeated headers into one value."""
    headers: dict[str, str] = {}
    for line in raw.splitlines()[1:]:
        if not line.strip():
            break
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key in headers:
            headers[key] = f"{headers[key]}, {value}"
        else:
            headers[key] = value
    return headers


def select_headers(headers: dict[str, str], show_all: bool) -> list[tuple[str, str]]:
    if show_all:
        return list(headers.items())
    lowered = {key.lower(): (key, value) for key, value in headers.items()}
    return [lowered[name.lower()] for name in INTERESTING_HEADERS if name.lower() in lowered]


def resolve_tls(args: argparse.Namespace) -> bool:
    if args.tls:
        return True
    if args.no_tls:
        return False
    return args.port in DEFAULT_TLS_PORTS


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Minimal HTTP/HTTPS service enumerator",
        epilog="Only probe hosts you own or are explicitly authorised to test.",
    )
    parser.add_argument("host", help="Target host or IP address")
    parser.add_argument("port", type=int, help="Target port (e.g. 80 or 443)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout in seconds")
    parser.add_argument(
        "--tls", action="store_true", help="Force TLS regardless of the port"
    )
    parser.add_argument(
        "--no-tls", action="store_true", help="Force plaintext regardless of the port"
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Skip certificate verification (needed for raw IPs and self-signed certs)",
    )
    parser.add_argument(
        "--server-name", help="Hostname to use for SNI and the Host header"
    )
    parser.add_argument(
        "--all-headers", action="store_true", help="Print every header, not just the notable ones"
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    if args.tls and args.no_tls:
        print("[!] --tls and --no-tls cannot be combined.", file=sys.stderr)
        return 2
    if not 0 < args.port <= 65535:
        print(f"[!] Port {args.port} is outside 1-65535.", file=sys.stderr)
        return 2
    if args.timeout <= 0:
        print("[!] --timeout must be greater than 0.", file=sys.stderr)
        return 2

    use_tls = resolve_tls(args)

    try:
        raw = fetch(
            args.host,
            args.port,
            use_tls=use_tls,
            timeout=args.timeout,
            insecure=args.insecure,
            server_name=args.server_name,
        )
    except EnumerationError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    status = parse_status_line(raw)
    headers = parse_headers(raw)
    selected = select_headers(headers, args.all_headers)

    if args.json:
        payload = {
            "host": args.host,
            "port": args.port,
            "scheme": "https" if use_tls else "http",
            "status_line": status,
            "headers": dict(selected),
        }
        print(json.dumps(payload, indent=2))
        return 0

    print(f"Service: {'HTTPS' if use_tls else 'HTTP'}  ({args.host}:{args.port})")
    if status:
        print(f"Status:  {status}")
    if selected:
        print()
        width = max(len(key) for key, _ in selected) + 1
        for key, value in selected:
            print(f"{(key + ':').ljust(width)} {value}")
    else:
        print("(No headers received)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

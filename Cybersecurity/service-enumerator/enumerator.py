from __future__ import annotations

import argparse
import socket
import ssl


def http_head(host: str, port: int, timeout: float = 2.0) -> str:
    request = (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: service-enumerator/1.0\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(request)
        data = sock.recv(4096)
    return data.decode(errors="ignore")


def https_head(host: str, port: int, timeout: float = 3.0) -> str:
    context = ssl.create_default_context()

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            request = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: service-enumerator/1.0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            tls_sock.sendall(request)
            data = tls_sock.recv(4096)
    return data.decode(errors="ignore")


def parse_headers(raw: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    lines = raw.splitlines()
    # Skip status line
    for line in lines[1:]:
        if not line.strip():
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def main() -> int:
    parser = argparse.ArgumentParser(description="Minimal service enumerator (HTTP/HTTPS)")
    parser.add_argument("host", help="Target host or IP")
    parser.add_argument("port", type=int, help="Target port (e.g., 80 or 443)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Timeout in seconds")
    args = parser.parse_args()

    is_tls = args.port in {443, 8443}

    try:
        raw = https_head(args.host, args.port, timeout=args.timeout) if is_tls else http_head(args.host, args.port, timeout=args.timeout)
    except Exception as e:
        print(f"[!] Connection failed: {e}")
        return 1

    headers = parse_headers(raw)

    print("Service:", "HTTPS" if is_tls else "HTTP")
    if headers:
        for key in ("Server", "X-Powered-By", "Via", "Date"):
            if key in headers:
                print(f"{key}: {headers[key]}")
    else:
        print("(No headers received)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

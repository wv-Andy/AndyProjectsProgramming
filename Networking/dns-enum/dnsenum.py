"""DNS enumeration tool.

Queries records, attempts a zone transfer, and brute-forces subdomains
concurrently. DNS messages are built and parsed by hand in `dnsproto`, so
nothing here depends on a resolver library.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import socket
import struct
import sys
from collections.abc import Sequence
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from dnsproto import (  # noqa: E402
    RECORD_TYPES,
    DNSError,
    Record,
    Response,
    build_query,
    parse_response,
)

DEFAULT_RESOLVER = "8.8.8.8"
DNS_PORT = 53
DEFAULT_TYPES = ("A", "AAAA", "NS", "MX", "TXT", "SOA", "CNAME", "CAA")

# A small built-in list, so the tool is useful without a wordlist file.
COMMON_SUBDOMAINS = (
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "ns1", "ns2",
    "dev", "staging", "test", "api", "admin", "portal", "vpn", "remote",
    "cpanel", "blog", "shop", "app", "cdn", "static", "assets", "img",
    "git", "gitlab", "jenkins", "jira", "confluence", "docs", "support",
    "internal", "intranet", "beta", "demo", "db", "database", "backup",
    "monitor", "grafana", "kibana", "status", "m", "mobile", "secure",
)


class QueryError(RuntimeError):
    """Raised when a query cannot be sent or answered."""


async def query(
    name: str,
    record_type: str,
    resolver: str,
    *,
    timeout: float,
) -> Response:
    """Send one UDP query and parse the reply."""
    loop = asyncio.get_running_loop()
    packet = build_query(name, record_type)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await loop.sock_sendto(sock, packet, (resolver, DNS_PORT))
        data = await asyncio.wait_for(loop.sock_recv(sock, 4096), timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise QueryError(f"{record_type} query for {name} timed out") from exc
    except OSError as exc:
        raise QueryError(f"{record_type} query for {name} failed: {exc}") from exc
    finally:
        sock.close()

    try:
        return parse_response(data)
    except DNSError as exc:
        raise QueryError(f"Malformed reply for {name}: {exc}") from exc


async def query_types(
    name: str,
    types: Sequence[str],
    resolver: str,
    *,
    timeout: float,
) -> dict[str, list[Record]]:
    """Query several record types at once."""

    async def one(record_type: str) -> tuple[str, list[Record]]:
        try:
            response = await query(name, record_type, resolver, timeout=timeout)
        except QueryError:
            return record_type, []
        return record_type, response.answers

    results = await asyncio.gather(*(one(record_type) for record_type in types))
    return {record_type: records for record_type, records in results if records}


async def resolve_exists(
    name: str,
    resolver: str,
    *,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> tuple[str, list[Record]]:
    """Check whether a name resolves, for the brute-force sweep."""
    async with semaphore:
        try:
            response = await query(name, "A", resolver, timeout=timeout)
        except QueryError:
            return name, []
        # NXDOMAIN means it does not exist. Anything else with answers does.
        if response.response_code != "NOERROR":
            return name, []
        return name, response.answers


async def brute_force(
    domain: str,
    words: Sequence[str],
    resolver: str,
    *,
    timeout: float,
    concurrency: int,
) -> list[tuple[str, list[Record]]]:
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [
        resolve_exists(f"{word}.{domain}", resolver, timeout=timeout, semaphore=semaphore)
        for word in words
    ]
    results = await asyncio.gather(*tasks)
    return [(name, records) for name, records in results if records]


async def detect_wildcard(domain: str, resolver: str, *, timeout: float) -> set[str]:
    """Find out whether the zone answers for names that should not exist.

    A wildcard record makes every brute-force guess look like a hit, so the
    addresses it returns have to be collected and then filtered out.
    """
    probes = [
        f"this-should-not-exist-{index}-zzz.{domain}" for index in range(3)
    ]
    addresses: set[str] = set()
    for probe in probes:
        try:
            response = await query(probe, "A", resolver, timeout=timeout)
        except QueryError:
            continue
        for record in response.answers:
            if record.type == "A":
                addresses.add(record.value)
    return addresses


def zone_transfer(domain: str, nameserver: str, *, timeout: float) -> list[Record]:
    """Attempt an AXFR against one nameserver.

    Zone transfer runs over TCP, and each message is prefixed with a two-byte
    length, because TCP gives no message boundaries of its own. A server that
    allows this to anyone hands over its entire zone: every host, every internal
    name. It is a real finding.
    """
    packet = build_query(domain, "AXFR")
    framed = struct.pack(">H", len(packet)) + packet

    records: list[Record] = []
    try:
        with socket.create_connection((nameserver, DNS_PORT), timeout=timeout) as sock:
            sock.sendall(framed)
            buffer = bytearray()

            while True:
                try:
                    chunk = sock.recv(65535)
                except TimeoutError:
                    break
                if not chunk:
                    break
                buffer.extend(chunk)

                # Pull out every complete length-prefixed message.
                while len(buffer) >= 2:
                    (length,) = struct.unpack(">H", buffer[:2])
                    if len(buffer) < length + 2:
                        break
                    message = bytes(buffer[2 : length + 2])
                    del buffer[: length + 2]
                    try:
                        records.extend(parse_response(message).answers)
                    except DNSError:
                        continue

                # The zone ends with a repeat of the opening SOA record.
                soa_count = sum(1 for record in records if record.type == "SOA")
                if soa_count >= 2:
                    return records
    except OSError as exc:
        raise QueryError(f"Zone transfer to {nameserver} failed: {exc}") from exc

    return records


def load_wordlist(path: Path | None) -> list[str]:
    if path is None:
        return list(COMMON_SUBDOMAINS)
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise QueryError(f"Could not read {path}: {exc}") from exc
    words = [line.strip().lower() for line in lines]
    return [word for word in words if word and not word.startswith("#")]


async def enumerate_domain(
    domain: str,
    resolver: str,
    *,
    timeout: float,
    concurrency: int,
    words: Sequence[str] | None,
    try_axfr: bool,
) -> dict:
    report: dict = {"domain": domain, "resolver": resolver}

    records = await query_types(domain, DEFAULT_TYPES, resolver, timeout=timeout)
    report["records"] = {
        record_type: [
            {"name": r.name, "type": r.type, "ttl": r.ttl, "value": r.value} for r in items
        ]
        for record_type, items in records.items()
    }

    nameservers = [record.value.rstrip(".") for record in records.get("NS", [])]
    report["nameservers"] = nameservers

    if try_axfr and nameservers:
        transfers = {}
        for nameserver in nameservers:
            try:
                transferred = zone_transfer(domain, nameserver, timeout=timeout)
            except QueryError as exc:
                transfers[nameserver] = {"allowed": False, "detail": str(exc)}
                continue
            if transferred:
                transfers[nameserver] = {
                    "allowed": True,
                    "record_count": len(transferred),
                    "records": [
                        {"name": r.name, "type": r.type, "value": r.value}
                        for r in transferred[:200]
                    ],
                }
            else:
                transfers[nameserver] = {"allowed": False, "detail": "Refused or empty"}
        report["zone_transfer"] = transfers

    if words:
        wildcard = await detect_wildcard(domain, resolver, timeout=timeout)
        report["wildcard_addresses"] = sorted(wildcard)

        found = await brute_force(
            domain, words, resolver, timeout=timeout, concurrency=concurrency
        )
        filtered = []
        for name, items in found:
            addresses = {record.value for record in items if record.type == "A"}
            # Drop anything that only ever points at the wildcard.
            if wildcard and addresses and addresses <= wildcard:
                continue
            filtered.append(
                {"name": name, "addresses": sorted(addresses)}
            )
        report["subdomains"] = filtered
        report["words_tried"] = len(words)

    return report


def print_report(report: dict) -> None:
    print(f"\nDNS enumeration: {report['domain']}")
    print("=" * 66)
    print(f"Resolver: {report['resolver']}")

    records = report.get("records", {})
    if records:
        print("\nRecords")
        print("-" * 66)
        for record_type, items in records.items():
            for item in items:
                print(f"  {record_type:<6} {item['ttl']:>7}  {item['value']}")
    else:
        print("\nNo records returned.")

    transfers = report.get("zone_transfer")
    if transfers:
        print("\nZone transfer (AXFR)")
        print("-" * 66)
        for nameserver, result in transfers.items():
            if result["allowed"]:
                print(f"  [!] {nameserver} ALLOWED the transfer: {result['record_count']} records")
                print("      This exposes the entire zone. It is a real finding.")
                for item in result["records"][:15]:
                    print(f"        {item['type']:<6} {item['name']} -> {item['value']}")
            else:
                print(f"  [ok] {nameserver} refused")

    if "subdomains" in report:
        wildcard = report.get("wildcard_addresses") or []
        if wildcard:
            print(f"\n  Note: this zone has a wildcard record ({', '.join(wildcard)}).")
            print("  Names resolving only to those addresses were filtered out.")

        print(f"\nSubdomains ({len(report['subdomains'])} of {report['words_tried']} tried)")
        print("-" * 66)
        for entry in report["subdomains"]:
            print(f"  {entry['name']:<40} {', '.join(entry['addresses'])}")
        if not report["subdomains"]:
            print("  None found.")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Enumerate DNS records, zone transfers and subdomains",
        epilog="Only enumerate domains you own or are authorised to test.",
    )
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument("--resolver", default=DEFAULT_RESOLVER, help="DNS server to query")
    parser.add_argument("--timeout", type=float, default=3.0, help="Timeout per query in seconds")
    parser.add_argument("--concurrency", type=int, default=50, help="Simultaneous queries")
    parser.add_argument(
        "--brute", action="store_true", help="Brute-force subdomains from the built-in list"
    )
    parser.add_argument(
        "--wordlist", type=Path, help="Use this wordlist instead of the built-in one"
    )
    parser.add_argument("--axfr", action="store_true", help="Attempt a zone transfer")
    parser.add_argument(
        "--type",
        dest="record_type",
        choices=sorted(RECORD_TYPES),
        help="Query a single record type instead of the default set",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    if args.timeout <= 0:
        print("[!] --timeout must be greater than 0.", file=sys.stderr)
        return 2
    if args.concurrency < 1:
        print("[!] --concurrency must be at least 1.", file=sys.stderr)
        return 2

    try:
        words = None
        if args.brute or args.wordlist:
            words = load_wordlist(args.wordlist)

        if args.record_type:
            response = asyncio.run(
                query(args.domain, args.record_type, args.resolver, timeout=args.timeout)
            )
            if args.json:
                print(
                    json.dumps(
                        {
                            "domain": args.domain,
                            "type": args.record_type,
                            "response_code": response.response_code,
                            "answers": [
                                {"name": r.name, "type": r.type, "ttl": r.ttl, "value": r.value}
                                for r in response.answers
                            ],
                        },
                        indent=2,
                    )
                )
            else:
                print(f"\n{args.domain} {args.record_type} -> {response.response_code}")
                for record in response.answers:
                    print(f"  {record.type:<6} {record.ttl:>7}  {record.value}")
                if not response.answers:
                    print("  No answers.")
            return 0

        report = asyncio.run(
            enumerate_domain(
                args.domain,
                args.resolver,
                timeout=args.timeout,
                concurrency=args.concurrency,
                words=words,
                try_axfr=args.axfr,
            )
        )
    except (QueryError, DNSError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

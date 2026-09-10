"""Vulnerability scanner.

Ties the earlier tools into one pipeline: scan ports, identify the service and
version on each open one, match those versions against a local CVE feed, and
produce a report ordered by severity.

This is the project that turns the port scanner and the service enumerator into
components of something larger. It reuses their code directly rather than
reimplementing it.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence
from pathlib import Path

# Reuse the port scanner from its sibling project.
SCANNER_DIR = Path(__file__).resolve().parent.parent / "async-port-scanner"
sys.path.insert(0, str(SCANNER_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import scanner  # noqa: E402
from vulndb import (  # noqa: E402
    DetectedService,
    FeedError,
    Match,
    load_feed,
    match_all,
    parse_banner,
)

DEFAULT_FEED = Path(__file__).resolve().parent / "feed.json"


def detect_services(results: Sequence) -> list[DetectedService]:
    """Extract product and version from the banners of open ports."""
    services: list[DetectedService] = []
    for result in results:
        if result.status != scanner.OPEN_STATUS or not result.banner:
            continue
        detected = parse_banner(result.banner, port=result.port)
        if detected is not None:
            services.append(detected)
    return services


async def scan_target(
    host: str,
    ports: Sequence[int],
    *,
    timeout: float,
    concurrency: int,
) -> list:
    """Run the port scan and return its open-port results."""
    results = await scanner.run_scan(host, ports, timeout=timeout, concurrency=concurrency)
    return [result for result in results if result.status == scanner.OPEN_STATUS]


def build_report(
    host: str,
    resolved: str,
    open_results: Sequence,
    services: Sequence[DetectedService],
    matches: Sequence[Match],
) -> dict:
    return {
        "target": host,
        "resolved_ip": resolved,
        "open_ports": [
            {"port": r.port, "service": r.service, "banner": r.banner} for r in open_results
        ],
        "detected_software": [
            {"product": s.product, "version": s.version, "port": s.port} for s in services
        ],
        "vulnerabilities": [
            {
                "cve": m.vulnerability.cve,
                "product": m.vulnerability.product,
                "version": m.detected_version,
                "port": m.port,
                "cvss": m.vulnerability.cvss,
                "severity": m.vulnerability.severity,
                "description": m.vulnerability.description,
            }
            for m in matches
        ],
    }


def print_report(report: dict) -> None:
    print(f"\nVulnerability scan: {report['target']} ({report['resolved_ip']})")
    print("=" * 70)

    open_ports = report["open_ports"]
    print(f"\nOpen ports ({len(open_ports)}):")
    for entry in open_ports:
        banner = f"  {entry['banner']}" if entry["banner"] else ""
        print(f"  {entry['port']:<6} {entry['service'] or 'unknown'}{banner}")

    software = report["detected_software"]
    if software:
        print(f"\nIdentified software ({len(software)}):")
        for entry in software:
            print(f"  {entry['product']} {entry['version']}  (port {entry['port']})")

    vulnerabilities = report["vulnerabilities"]
    print(f"\nVulnerabilities ({len(vulnerabilities)}):")
    print("-" * 70)
    if not vulnerabilities:
        print("  None matched the feed. This is not a clean bill of health, only")
        print("  that nothing in the local feed applied to the detected versions.")
        return

    for vuln in vulnerabilities:
        print(
            f"  [{vuln['severity'].upper()}] {vuln['cve']}  "
            f"CVSS {vuln['cvss']}  ({vuln['product']} {vuln['version']}, port {vuln['port']})"
        )
        print(f"      {vuln['description']}")
        print()

    worst = vulnerabilities[0]
    print(f"Most serious: {worst['cve']} at CVSS {worst['cvss']}.")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan a host, identify services and match them against a CVE feed",
        epilog="Only scan hosts you own or are explicitly authorised to test.",
    )
    parser.add_argument("host", help="Target host or IP address")
    parser.add_argument("--ports", help="Ports to scan, e.g. 22,80,443,8000-8100")
    parser.add_argument("--top", action="store_true", help="Scan a curated list of common ports")
    parser.add_argument("--timeout", type=float, default=2.0, help="Timeout per port in seconds")
    parser.add_argument("--concurrency", type=int, default=200, help="Simultaneous connections")
    parser.add_argument("--feed", type=Path, default=DEFAULT_FEED, help="CVE feed JSON file")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    return parser.parse_args(argv)


def resolve_ports(args: argparse.Namespace) -> list[int]:
    if args.ports:
        return scanner.parse_port_spec(args.ports)
    if args.top:
        return sorted(scanner.TOP_PORTS)
    return sorted(scanner.TOP_PORTS)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    if args.timeout <= 0 or args.concurrency < 1:
        print("[!] --timeout must be > 0 and --concurrency at least 1.", file=sys.stderr)
        return 2

    try:
        feed = load_feed(args.feed)
        ports = resolve_ports(args)
        resolved = scanner.resolve_host(args.host)
    except (FeedError, scanner.PortSpecError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    open_results = asyncio.run(
        scan_target(args.host, ports, timeout=args.timeout, concurrency=args.concurrency)
    )
    services = detect_services(open_results)
    matches = match_all(services, feed)

    report = build_report(args.host, resolved, open_results, services, matches)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)

    # Non-zero exit if anything critical or high was found, so CI can gate on it.
    if any(match.vulnerability.severity in ("critical", "high") for match in matches):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

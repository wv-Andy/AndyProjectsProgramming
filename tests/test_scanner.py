"""Tests for the async port scanner."""

from __future__ import annotations

import asyncio
import io
import socket

import pytest


def test_parse_port_spec_expands_lists_and_ranges(scanner):
    assert scanner.parse_port_spec("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]


def test_parse_port_spec_deduplicates_and_sorts(scanner):
    assert scanner.parse_port_spec("80,22,80,22") == [22, 80]


def test_parse_port_spec_ignores_empty_tokens(scanner):
    assert scanner.parse_port_spec("22,,80,") == [22, 80]


def test_parse_port_spec_rejects_non_numeric(scanner):
    with pytest.raises(scanner.PortSpecError):
        scanner.parse_port_spec("80,abc")


def test_parse_port_spec_rejects_reversed_range(scanner):
    with pytest.raises(scanner.PortSpecError):
        scanner.parse_port_spec("8100-8000")


def test_parse_port_spec_rejects_out_of_range(scanner):
    with pytest.raises(scanner.PortSpecError):
        scanner.parse_port_spec("70000")
    with pytest.raises(scanner.PortSpecError):
        scanner.parse_port_spec("0")


def test_lookup_service_never_raises_on_unassigned_port(scanner):
    """The unguarded version of this call is what mislabelled open ports."""
    assert scanner.lookup_service(1000) is None
    assert scanner.lookup_service(80) == "http"


def test_build_probe_uses_the_real_host_in_the_host_header(scanner):
    probe = scanner.build_probe("example.com", 80, "http")
    assert b"Host: example.com" in probe
    assert b"Host: localhost" not in probe


def test_build_probe_covers_alternate_http_ports(scanner):
    assert scanner.build_probe("example.com", 8080, None) is not None


def test_build_probe_skips_tls_ports(scanner):
    assert scanner.build_probe("example.com", 443, "https") is None


def test_clean_banner_strips_control_characters(scanner):
    assert scanner.clean_banner(b"SSH-2.0-OpenSSH_8.9\r\n") == "SSH-2.0-OpenSSH_8.9"
    assert scanner.clean_banner(b"\x00\x01") is None
    assert scanner.clean_banner(b"") is None


def test_pretty_header_falls_back_to_ascii(scanner):
    ascii_header = scanner.pretty_header("host", "host", unicode_ok=False)
    ascii_header.encode("cp1252")  # must not raise
    assert "═" not in ascii_header


def test_supports_unicode_detects_a_cp1252_stream(scanner):
    cp1252_stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    utf8_stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    assert scanner.supports_unicode(cp1252_stream) is False
    assert scanner.supports_unicode(utf8_stream) is True


def test_resolve_host_reports_a_bad_name(scanner):
    with pytest.raises(scanner.PortSpecError):
        scanner.resolve_host("no-such-host.invalid")


def test_summarise_counts_every_status(scanner):
    results = [
        scanner.PortScanResult(port=1, status=scanner.OPEN_STATUS),
        scanner.PortScanResult(port=2, status=scanner.CLOSED_STATUS),
        scanner.PortScanResult(port=3, status=scanner.CLOSED_STATUS),
    ]
    counts = scanner.summarise(results)
    assert counts[scanner.OPEN_STATUS] == 1
    assert counts[scanner.CLOSED_STATUS] == 2
    assert counts[scanner.FILTERED_STATUS] == 0


def test_format_result_includes_the_banner(scanner):
    result = scanner.PortScanResult(
        port=22, status=scanner.OPEN_STATUS, service="ssh", banner="SSH-2.0"
    )
    line = scanner.format_result(result)
    assert "OPEN" in line and "22" in line and "SSH-2.0" in line


@pytest.fixture
def listening_port():
    """Bind a real listener on a port with no entry in the services database."""
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    yield server.getsockname()[1]
    server.close()


def test_open_port_without_a_service_name_is_reported_open(scanner, listening_port):
    """Regression test: an open port used to be reported as CLOSED.

    ``socket.getservbyport`` raises for unassigned ports. That OSError escaped
    the banner grab and was caught by the connect handler, which reported the
    port closed even though the connection had succeeded.
    """

    async def run():
        semaphore = asyncio.Semaphore(4)
        return await scanner.probe_port(
            "127.0.0.1", listening_port, timeout=2.0, semaphore=semaphore
        )

    result = asyncio.run(run())
    assert result.status == scanner.OPEN_STATUS


def test_closed_port_is_reported_closed(scanner):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    async def run():
        semaphore = asyncio.Semaphore(4)
        return await scanner.probe_port("127.0.0.1", port, timeout=2.0, semaphore=semaphore)

    result = asyncio.run(run())
    assert result.status in {scanner.CLOSED_STATUS, scanner.FILTERED_STATUS}


def test_build_report_shape(scanner):
    results = [
        scanner.PortScanResult(port=22, status=scanner.OPEN_STATUS, service="ssh"),
        scanner.PortScanResult(port=23, status=scanner.CLOSED_STATUS),
    ]
    report = scanner.build_report(
        "example.com", "1.2.3.4", results, duration=1.0, include_closed=False
    )
    assert report["target"] == "example.com"
    assert report["resolved_ip"] == "1.2.3.4"
    assert report["ports_scanned"] == 2
    assert [entry["port"] for entry in report["results"]] == [22]

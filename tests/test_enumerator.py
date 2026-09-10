"""Tests for the HTTP/HTTPS service enumerator."""

from __future__ import annotations

import pytest


class FakeSocket:
    """A socket stand-in that hands back the response in fixed-size slices."""

    def __init__(self, payload: bytes, chunk: int = 8):
        self._payload = payload
        self._chunk = chunk
        self._offset = 0

    def recv(self, _size: int) -> bytes:
        piece = self._payload[self._offset : self._offset + self._chunk]
        self._offset += len(piece)
        return piece


def test_read_response_reassembles_split_headers(enumerator):
    payload = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nX-Powered-By: PHP\r\n\r\n"
    raw = enumerator.read_response(FakeSocket(payload, chunk=7))
    assert raw == payload


def test_read_response_stops_when_the_peer_closes(enumerator):
    raw = enumerator.read_response(FakeSocket(b"HTTP/1.1 200 OK\r\n", chunk=4))
    assert raw == b"HTTP/1.1 200 OK\r\n"


def test_read_response_honours_the_limit(enumerator):
    raw = enumerator.read_response(FakeSocket(b"A" * 10_000, chunk=100), limit=256)
    assert len(raw) <= 256 + 100


def test_parse_headers_folds_repeated_keys(enumerator):
    raw = "HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n"
    headers = enumerator.parse_headers(raw)
    assert headers["Set-Cookie"] == "a=1, b=2"


def test_parse_headers_stops_at_the_blank_line(enumerator):
    raw = "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nBody: not-a-header\r\n"
    headers = enumerator.parse_headers(raw)
    assert "Server" in headers
    assert "Body" not in headers


def test_parse_status_line(enumerator):
    assert enumerator.parse_status_line("HTTP/1.1 301 Moved\r\n") == "HTTP/1.1 301 Moved"
    assert enumerator.parse_status_line("") is None


def test_select_headers_is_case_insensitive(enumerator):
    headers = {"server": "nginx", "X-Random": "1"}
    selected = enumerator.select_headers(headers, show_all=False)
    assert selected == [("server", "nginx")]


def test_select_headers_show_all_keeps_everything(enumerator):
    headers = {"Server": "nginx", "X-Random": "1"}
    assert len(enumerator.select_headers(headers, show_all=True)) == 2


def test_is_ip_literal(enumerator):
    assert enumerator.is_ip_literal("192.0.2.1") is True
    assert enumerator.is_ip_literal("::1") is True
    assert enumerator.is_ip_literal("example.com") is False


def test_build_request_sets_the_host_header(enumerator):
    request = enumerator.build_request("example.com:8080")
    assert b"Host: example.com:8080" in request
    assert b"Connection: close" in request


@pytest.mark.parametrize(
    ("port", "tls", "no_tls", "expected"),
    [
        (443, False, False, True),
        (80, False, False, False),
        (9443, False, False, True),
        (8080, True, False, True),
        (443, False, True, False),
    ],
)
def test_resolve_tls(enumerator, port, tls, no_tls, expected):
    args = enumerator.parse_args(["example.com", str(port)])
    args.tls = tls
    args.no_tls = no_tls
    assert enumerator.resolve_tls(args) is expected


def test_raw_ip_over_tls_without_insecure_is_refused(enumerator):
    """Verifying a certificate against a bare IP cannot work; say so clearly."""
    with pytest.raises(enumerator.EnumerationError) as excinfo:
        enumerator.fetch(
            "192.0.2.1",
            443,
            use_tls=True,
            timeout=0.2,
            insecure=False,
            server_name=None,
        )
    message = str(excinfo.value)
    assert "--insecure" in message or "Connection failed" in message


def test_rejects_conflicting_tls_flags(enumerator):
    assert enumerator.main(["example.com", "443", "--tls", "--no-tls"]) == 2


def test_rejects_an_out_of_range_port(enumerator):
    assert enumerator.main(["example.com", "70000"]) == 2

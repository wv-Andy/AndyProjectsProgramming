"""Tests for the hand-built DNS message encoder and parser."""

from __future__ import annotations

import struct

import pytest

# --- Name encoding --------------------------------------------------------


def test_encode_name_uses_length_prefixed_labels(dnsproto):
    assert dnsproto.encode_name("example.com") == b"\x07example\x03com\x00"


def test_encode_name_handles_a_trailing_dot(dnsproto):
    assert dnsproto.encode_name("example.com.") == dnsproto.encode_name("example.com")


def test_encode_name_rejects_an_over_long_label(dnsproto):
    with pytest.raises(dnsproto.DNSError):
        dnsproto.encode_name("a" * 64 + ".com")


def test_decode_name_reads_back_what_encode_wrote(dnsproto):
    encoded = dnsproto.encode_name("www.example.com")
    name, offset = dnsproto.decode_name(encoded, 0)
    assert name == "www.example.com"
    assert offset == len(encoded)


def test_decode_name_follows_a_compression_pointer(dnsproto):
    # "example.com" at offset 0, then a name "www" + pointer back to offset 0.
    base = dnsproto.encode_name("example.com")
    message = base + b"\x03www" + struct.pack(">H", 0xC000)
    name, _ = dnsproto.decode_name(message, len(base))
    assert name == "www.example.com"


def test_decode_name_reports_the_offset_after_the_pointer(dnsproto):
    base = dnsproto.encode_name("example.com")
    pointer_at = len(base) + 4
    message = base + b"\x03www" + struct.pack(">H", 0xC000)
    _, offset = dnsproto.decode_name(message, len(base))
    # The name ends right after the two pointer bytes, not at the target.
    assert offset == pointer_at + 2


def test_decode_name_rejects_a_pointer_loop(dnsproto):
    # A pointer at offset 0 pointing to itself.
    message = struct.pack(">H", 0xC000)
    with pytest.raises(dnsproto.DNSError):
        dnsproto.decode_name(message, 0)


def test_decode_name_rejects_a_label_past_the_end(dnsproto):
    with pytest.raises(dnsproto.DNSError):
        dnsproto.decode_name(b"\x10abc", 0)


# --- Query construction ---------------------------------------------------


def test_build_query_header_and_question(dnsproto):
    packet = dnsproto.build_query("example.com", "A", transaction_id=0x1234)
    identifier, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", packet[:12])
    assert identifier == 0x1234
    assert flags == 0x0100  # recursion desired
    assert (qd, an, ns, ar) == (1, 0, 0, 0)
    assert packet[12:].startswith(b"\x07example\x03com\x00")
    qtype, qclass = struct.unpack(">HH", packet[-4:])
    assert qtype == dnsproto.RECORD_TYPES["A"]
    assert qclass == dnsproto.CLASS_IN


def test_build_query_rejects_an_unknown_type(dnsproto):
    with pytest.raises(dnsproto.DNSError):
        dnsproto.build_query("example.com", "NONSENSE")


def test_build_query_randomises_the_transaction_id(dnsproto):
    ids = {struct.unpack(">H", dnsproto.build_query("example.com", "A")[:2])[0] for _ in range(50)}
    # Fifty random 16-bit ids should almost never all collide.
    assert len(ids) > 1


# --- Response parsing -----------------------------------------------------


def build_message(dnsproto, answers, *, rcode=0, flags_extra=0):
    """Assemble a minimal DNS response carrying one question and some answers."""
    header = struct.pack(">HHHHHH", 0x1234, 0x8180 | rcode | flags_extra, 1, len(answers), 0, 0)
    body = dnsproto.encode_name("example.com") + struct.pack(">HH", 1, 1)
    for record_type, rdata in answers:
        body += b"\xc0\x0c"  # pointer to the question name at offset 12
        body += struct.pack(">HHIH", record_type, 1, 300, len(rdata))
        body += rdata
    return header + body


def test_parse_response_reads_an_a_record(dnsproto):
    message = build_message(dnsproto, [(dnsproto.RECORD_TYPES["A"], bytes([93, 184, 216, 34]))])
    response = dnsproto.parse_response(message)
    assert response.response_code == "NOERROR"
    assert response.answers[0].type == "A"
    assert response.answers[0].value == "93.184.216.34"
    assert response.answers[0].name == "example.com"


def test_parse_response_reads_a_txt_record(dnsproto):
    rdata = b"\x0bv=spf1 -all"
    message = build_message(dnsproto, [(dnsproto.RECORD_TYPES["TXT"], rdata)])
    assert dnsproto.parse_response(message).answers[0].value == "v=spf1 -all"


def test_parse_response_reads_an_mx_record(dnsproto):
    rdata = struct.pack(">H", 10) + dnsproto.encode_name("mail.example.com")
    message = build_message(dnsproto, [(dnsproto.RECORD_TYPES["MX"], rdata)])
    assert dnsproto.parse_response(message).answers[0].value == "10 mail.example.com"


def test_parse_response_reads_an_aaaa_record(dnsproto):
    rdata = bytes.fromhex("20010db8000000000000000000000001")
    message = build_message(dnsproto, [(dnsproto.RECORD_TYPES["AAAA"], rdata)])
    value = dnsproto.parse_response(message).answers[0].value
    assert value.startswith("2001:db8")


def test_parse_response_surfaces_nxdomain(dnsproto):
    message = build_message(dnsproto, [], rcode=3)
    assert dnsproto.parse_response(message).response_code == "NXDOMAIN"


def test_parse_response_reads_the_authoritative_flag(dnsproto):
    message = build_message(dnsproto, [], flags_extra=0x0400)
    assert dnsproto.parse_response(message).authoritative is True


def test_parse_response_rejects_a_short_message(dnsproto):
    with pytest.raises(dnsproto.DNSError):
        dnsproto.parse_response(b"\x00\x01")


def test_parse_response_round_trips_with_build_query(dnsproto):
    """A query is not a response, but its header must still parse."""
    packet = dnsproto.build_query("example.com", "A", transaction_id=0xABCD)
    parsed = dnsproto.parse_response(packet)
    assert parsed.transaction_id == 0xABCD
    assert parsed.questions == ["example.com"]

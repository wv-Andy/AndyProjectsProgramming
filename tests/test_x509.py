"""Tests for the hand-written DER/ASN.1 certificate parser."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path

import pytest

DATA = Path(__file__).resolve().parent / "data"


# --- DER primitives -------------------------------------------------------


def test_read_node_short_form_length(x509):
    # INTEGER, length 1, value 5
    node = x509.read_node(bytes([0x02, 0x01, 0x05]))
    assert node.tag == x509.TAG_INTEGER
    assert node.value == b"\x05"
    assert node.end == 3


def test_read_node_long_form_length(x509):
    # OCTET STRING, long form length 0x81 0x80 means 128 content bytes
    payload = bytes([0x04, 0x81, 0x80]) + b"A" * 128
    node = x509.read_node(payload)
    assert len(node.value) == 128
    assert node.end == len(payload)


def test_read_node_rejects_truncated_value(x509):
    with pytest.raises(x509.DERError):
        x509.read_node(bytes([0x02, 0x08, 0x01]))


def test_read_node_rejects_indefinite_length(x509):
    with pytest.raises(x509.DERError):
        x509.read_node(bytes([0x30, 0x80, 0x00, 0x00]))


def test_read_node_rejects_empty_input(x509):
    with pytest.raises(x509.DERError):
        x509.read_node(b"")


def test_read_children_splits_a_sequence(x509):
    # SEQUENCE { INTEGER 1, INTEGER 2 }
    node = x509.read_node(bytes([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]))
    children = x509.read_children(node)
    assert [child.value for child in children] == [b"\x01", b"\x02"]


def test_decode_oid_packs_the_first_two_arcs(x509):
    # 2.5.4.3 (commonName): first byte 0x55 == 85 == 2*40 + 5
    assert x509.decode_oid(bytes([0x55, 0x04, 0x03])) == "2.5.4.3"


def test_decode_oid_handles_multi_byte_arcs(x509):
    # 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
    encoded = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B])
    assert x509.decode_oid(encoded) == "1.2.840.113549.1.1.11"


def test_decode_oid_rejects_empty(x509):
    with pytest.raises(x509.DERError):
        x509.decode_oid(b"")


def test_decode_oid_rejects_truncated_arc(x509):
    with pytest.raises(x509.DERError):
        x509.decode_oid(bytes([0x2A, 0x86]))


# --- Time handling --------------------------------------------------------


def make_time_node(x509, tag, text):
    return x509.Node(tag=tag, value=text.encode(), end=0)


def test_utctime_before_2050_is_twenty_first_century(x509):
    node = make_time_node(x509, x509.TAG_UTC_TIME, "250412235959Z")
    assert x509.decode_time(node) == datetime(2025, 4, 12, 23, 59, 59, tzinfo=timezone.utc)


def test_utctime_from_fifty_onwards_is_twentieth_century(x509):
    """RFC 5280 puts the pivot at 50, which is not where strptime puts it."""
    node = make_time_node(x509, x509.TAG_UTC_TIME, "500101000000Z")
    assert x509.decode_time(node).year == 1950
    node = make_time_node(x509, x509.TAG_UTC_TIME, "490101000000Z")
    assert x509.decode_time(node).year == 2049


def test_generalized_time(x509):
    node = make_time_node(x509, x509.TAG_GENERALIZED_TIME, "20351231120000Z")
    assert x509.decode_time(node).year == 2035


def test_decode_time_rejects_a_local_offset(x509):
    node = make_time_node(x509, x509.TAG_UTC_TIME, "250412235959+0200")
    with pytest.raises(x509.DERError):
        x509.decode_time(node)


# --- A real certificate ---------------------------------------------------


@pytest.fixture(scope="session")
def isrg_root(x509):
    """ISRG Root X1, a stable public root certificate used as a fixture."""
    pem = (DATA / "isrg-root-x1.pem").read_text(encoding="ascii")
    return x509.parse_certificate(ssl.PEM_cert_to_DER_cert(pem))


def test_parses_subject_and_issuer(isrg_root):
    assert isrg_root.subject["CN"] == "ISRG Root X1"
    assert isrg_root.subject["O"] == "Internet Security Research Group"
    assert isrg_root.subject["C"] == "US"


def test_root_certificate_is_self_signed(isrg_root):
    assert isrg_root.is_self_signed is True


def test_parses_validity_dates(isrg_root):
    assert isrg_root.not_before.year == 2015
    assert isrg_root.not_after.year == 2035
    assert isrg_root.not_before < isrg_root.not_after


def test_parses_the_public_key(isrg_root):
    assert isrg_root.public_key_algorithm == "RSA"
    assert isrg_root.public_key_bits == 4096


def test_parses_the_signature_algorithm(isrg_root):
    assert isrg_root.signature_algorithm == "sha256WithRSAEncryption"
    assert isrg_root.has_weak_signature is False


def test_certificate_is_a_certificate_authority(isrg_root):
    assert isrg_root.is_ca is True


def test_version_is_v3(isrg_root):
    assert isrg_root.version == 3


def test_serial_number_is_a_positive_integer(isrg_root):
    assert isrg_root.serial_number > 0


def test_rejects_input_that_is_not_a_certificate(x509):
    with pytest.raises(x509.DERError):
        x509.parse_certificate(bytes([0x02, 0x01, 0x05]))


# --- Cross-check against the standard library ------------------------------


@pytest.mark.network
def test_parser_agrees_with_the_standard_library(x509):
    """Parse a live certificate both ways and compare the results.

    ``ssl.getpeercert`` returns a parsed dict only when the chain verifies, so
    this doubles as a check that the hand-written parser reads the same bytes
    the same way OpenSSL does.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection(("example.com", 443), timeout=15) as sock:
            with context.wrap_socket(sock, server_hostname="example.com") as tls:
                parsed_by_openssl = tls.getpeercert()
                der = tls.getpeercert(binary_form=True)
    except OSError as exc:
        pytest.skip(f"Network unavailable: {exc}")

    mine = x509.parse_certificate(der)

    subject = {key: value for rdn in parsed_by_openssl["subject"] for key, value in rdn}
    assert mine.subject["CN"] == subject["commonName"]

    openssl_names = sorted(
        value for kind, value in parsed_by_openssl.get("subjectAltName", ()) if kind == "DNS"
    )
    assert sorted(mine.dns_names) == openssl_names

    expiry = datetime.strptime(parsed_by_openssl["notAfter"], "%b %d %H:%M:%S %Y %Z")
    assert mine.not_after.replace(tzinfo=None) == expiry

"""Tests for the packet decoders.

Packets are built by hand from their header layouts, decoded, and checked field
by field. No socket is ever opened.
"""

from __future__ import annotations

import struct

import pytest


def build_ipv4(payload: bytes, *, protocol: int, src="192.168.1.10", dst="93.184.216.34") -> bytes:
    version_ihl = (4 << 4) | 5  # version 4, header length 5 words = 20 bytes
    total_length = 20 + len(payload)
    header = struct.pack(
        ">BBHHHBBH4s4s",
        version_ihl,
        0,  # DSCP/ECN
        total_length,
        0,  # identification
        0,  # flags/fragment
        64,  # ttl
        protocol,
        0,  # checksum, ignored by the decoder
        bytes(int(part) for part in src.split(".")),
        bytes(int(part) for part in dst.split(".")),
    )
    return header + payload


def build_tcp(payload: bytes = b"", *, src_port=12345, dst_port=80, flags=0x02) -> bytes:
    data_offset_flags = (5 << 12) | flags  # 5 words = 20 byte header
    header = struct.pack(
        ">HHIIHHHH",
        src_port,
        dst_port,
        1000,  # sequence
        0,  # ack
        data_offset_flags,
        65535,  # window
        0,  # checksum
        0,  # urgent pointer
    )
    return header + payload


def build_udp(payload: bytes = b"", *, src_port=53, dst_port=33333) -> bytes:
    return struct.pack(">HHHH", src_port, dst_port, 8 + len(payload), 0) + payload


def build_ethernet(payload: bytes, ethertype: int) -> bytes:
    return struct.pack(
        ">6s6sH",
        bytes.fromhex("aabbccddeeff"),
        bytes.fromhex("112233445566"),
        ethertype,
    ) + payload


# --- Formatting helpers ---------------------------------------------------


def test_format_mac(decode):
    assert decode.format_mac(bytes.fromhex("aabbccddeeff")) == "aa:bb:cc:dd:ee:ff"


def test_format_ipv4(decode):
    assert decode.format_ipv4(bytes([192, 168, 1, 1])) == "192.168.1.1"


def test_format_ipv6_trims_leading_zeros(decode):
    raw = bytes.fromhex("20010db8000000000000000000000001")
    assert decode.format_ipv6(raw) == "2001:db8:0:0:0:0:0:1"


# --- Ethernet -------------------------------------------------------------


def test_decode_ethernet(decode):
    frame = build_ethernet(b"payload", decode.ETHERTYPE_IPV4)
    ethernet = decode.decode_ethernet(frame)
    assert ethernet.source == "11:22:33:44:55:66"
    assert ethernet.destination == "aa:bb:cc:dd:ee:ff"
    assert ethernet.ethertype == decode.ETHERTYPE_IPV4
    assert ethernet.ethertype_name == "IPv4"
    assert ethernet.payload == b"payload"


def test_decode_ethernet_rejects_a_runt(decode):
    with pytest.raises(decode.DecodeError):
        decode.decode_ethernet(b"\x00" * 10)


# --- IPv4 -----------------------------------------------------------------


def test_decode_ipv4(decode):
    packet = build_ipv4(b"data", protocol=decode.PROTO_TCP)
    ip = decode.decode_ipv4(packet)
    assert ip.version == 4
    assert ip.header_length == 20
    assert ip.ttl == 64
    assert ip.protocol == decode.PROTO_TCP
    assert ip.protocol_name == "TCP"
    assert ip.source == "192.168.1.10"
    assert ip.destination == "93.184.216.34"
    assert ip.payload == b"data"


def test_decode_ipv4_rejects_a_short_buffer(decode):
    with pytest.raises(decode.DecodeError):
        decode.decode_ipv4(b"\x45" + b"\x00" * 5)


def test_decode_ipv4_rejects_a_bad_header_length(decode):
    # IHL of 3 words = 12 bytes, below the 20-byte minimum.
    bad = bytes([(4 << 4) | 3]) + b"\x00" * 19
    with pytest.raises(decode.DecodeError):
        decode.decode_ipv4(bad)


# --- IPv6 -----------------------------------------------------------------


def test_decode_ipv6(decode):
    header = struct.pack(
        ">IHBB",
        6 << 28,  # version in the top nibble
        16,  # payload length
        decode.PROTO_UDP,
        64,  # hop limit
    )
    header += bytes.fromhex("20010db8000000000000000000000001")  # source
    header += bytes.fromhex("20010db8000000000000000000000002")  # destination
    ip = decode.decode_ipv6(header + b"x" * 16)
    assert ip.version == 6
    assert ip.next_header == decode.PROTO_UDP
    assert ip.hop_limit == 64
    assert ip.source.startswith("2001:db8")


# --- TCP and UDP ----------------------------------------------------------


def test_decode_tcp_flags(decode):
    segment = build_tcp(flags=0x12)  # SYN + ACK
    tcp = decode.decode_tcp(segment)
    assert tcp.source_port == 12345
    assert tcp.destination_port == 80
    assert set(tcp.flag_names) == {"SYN", "ACK"}


def test_decode_tcp_single_flag(decode):
    assert decode.decode_tcp(build_tcp(flags=0x02)).flag_names == ["SYN"]
    assert decode.decode_tcp(build_tcp(flags=0x11)).flag_names == ["FIN", "ACK"]


def test_decode_udp(decode):
    datagram = build_udp(b"hello", src_port=53, dst_port=33333)
    udp = decode.decode_udp(datagram)
    assert udp.source_port == 53
    assert udp.destination_port == 33333
    assert udp.length == 13
    assert udp.payload == b"hello"


def test_decode_icmp(decode):
    packet = bytes([8, 0, 0, 0]) + b"ping"  # echo request
    icmp = decode.decode_icmp(packet)
    assert icmp.type == 8
    assert icmp.code == 0
    assert icmp.payload == b"ping"


# --- Full stack -----------------------------------------------------------


def test_decode_packet_ethernet_ipv4_tcp(decode):
    frame = build_ethernet(
        build_ipv4(build_tcp(b"GET / HTTP/1.1", flags=0x18), protocol=decode.PROTO_TCP),
        decode.ETHERTYPE_IPV4,
    )
    packet = decode.decode_packet(frame, link_layer=True)
    assert packet.link is not None
    assert packet.network.protocol_name == "TCP"
    assert isinstance(packet.transport, decode.TCP)
    assert packet.transport.payload == b"GET / HTTP/1.1"
    assert set(packet.transport.flag_names) == {"PSH", "ACK"}


def test_decode_packet_raw_ip_without_ethernet(decode):
    """Windows raw sockets deliver IP packets with no Ethernet header."""
    raw = build_ipv4(build_udp(b"data"), protocol=decode.PROTO_UDP)
    packet = decode.decode_packet(raw, link_layer=False)
    assert packet.link is None
    assert isinstance(packet.transport, decode.UDP)


def test_decode_packet_notes_a_non_ip_ethertype(decode):
    frame = build_ethernet(b"\x00" * 20, decode.ETHERTYPE_ARP)
    packet = decode.decode_packet(frame, link_layer=True)
    assert packet.network is None
    assert packet.notes


# --- Summaries ------------------------------------------------------------


def test_summarise_tcp(decode):
    frame = build_ethernet(
        build_ipv4(build_tcp(flags=0x02), protocol=decode.PROTO_TCP), decode.ETHERTYPE_IPV4
    )
    line = decode.summarise(decode.decode_packet(frame))
    assert line.startswith("TCP")
    assert "SYN" in line
    assert "192.168.1.10:12345" in line


def test_summarise_udp(decode):
    frame = build_ethernet(
        build_ipv4(build_udp(src_port=53), protocol=decode.PROTO_UDP), decode.ETHERTYPE_IPV4
    )
    assert decode.summarise(decode.decode_packet(frame)).startswith("UDP")


def test_summarise_non_ip(decode):
    frame = build_ethernet(b"\x00" * 20, decode.ETHERTYPE_ARP)
    assert "non-IP" in decode.summarise(decode.decode_packet(frame))

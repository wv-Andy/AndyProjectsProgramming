"""Tests for the sniffer's filter logic, which needs no socket."""

from __future__ import annotations


def make_tcp_packet(sniffer_decode, *, src_port=12345, dst_port=80):
    from test_packet_decode import build_ethernet, build_ipv4, build_tcp

    frame = build_ethernet(
        build_ipv4(
            build_tcp(src_port=src_port, dst_port=dst_port), protocol=sniffer_decode.PROTO_TCP
        ),
        sniffer_decode.ETHERTYPE_IPV4,
    )
    return sniffer_decode.decode_packet(frame)


def make_udp_packet(sniffer_decode, *, src_port=53, dst_port=33333):
    from test_packet_decode import build_ethernet, build_ipv4, build_udp

    frame = build_ethernet(
        build_ipv4(
            build_udp(src_port=src_port, dst_port=dst_port), protocol=sniffer_decode.PROTO_UDP
        ),
        sniffer_decode.ETHERTYPE_IPV4,
    )
    return sniffer_decode.decode_packet(frame)


def test_no_filter_matches_everything(sniffer, decode):
    packet = make_tcp_packet(decode)
    assert sniffer.matches_filter(packet, protocol=None, port=None) is True


def test_protocol_filter(sniffer, decode):
    tcp = make_tcp_packet(decode)
    udp = make_udp_packet(decode)
    assert sniffer.matches_filter(tcp, protocol="tcp", port=None) is True
    assert sniffer.matches_filter(udp, protocol="tcp", port=None) is False
    assert sniffer.matches_filter(udp, protocol="udp", port=None) is True


def test_port_filter_matches_either_direction(sniffer, decode):
    packet = make_tcp_packet(decode, src_port=12345, dst_port=80)
    assert sniffer.matches_filter(packet, protocol=None, port=80) is True
    assert sniffer.matches_filter(packet, protocol=None, port=12345) is True
    assert sniffer.matches_filter(packet, protocol=None, port=443) is False


def test_protocol_and_port_together(sniffer, decode):
    packet = make_tcp_packet(decode, dst_port=443)
    assert sniffer.matches_filter(packet, protocol="tcp", port=443) is True
    assert sniffer.matches_filter(packet, protocol="udp", port=443) is False


def test_port_filter_rejects_a_non_transport_packet(sniffer, decode):
    from test_packet_decode import build_ethernet

    arp = decode.decode_packet(build_ethernet(b"\x00" * 20, decode.ETHERTYPE_ARP))
    assert sniffer.matches_filter(arp, protocol=None, port=80) is False


def test_cli_rejects_a_bad_port(sniffer):
    assert sniffer.main(["--port", "70000"]) == 2

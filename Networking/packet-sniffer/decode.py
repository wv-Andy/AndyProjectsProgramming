"""Decoders for Ethernet, IPv4, IPv6, TCP, UDP and ICMP headers.

Every function takes raw bytes and returns a dataclass. There is no socket code
here, so the whole module is testable against captured or hand-built packets.

The layouts come from the RFCs: Ethernet II, RFC 791 (IPv4), RFC 8200 (IPv6),
RFC 793 (TCP), RFC 768 (UDP) and RFC 792 (ICMP). The recurring tool is
``struct.unpack`` with a big-endian format, because network byte order is
big-endian.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58

PROTOCOL_NAMES = {
    PROTO_ICMP: "ICMP",
    PROTO_TCP: "TCP",
    PROTO_UDP: "UDP",
    PROTO_ICMPV6: "ICMPv6",
}

# TCP flag bits, low to high.
TCP_FLAGS = (
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
)


class DecodeError(ValueError):
    """Raised when a buffer is too short or malformed for the layer."""


@dataclass
class Ethernet:
    destination: str
    source: str
    ethertype: int
    payload: bytes

    @property
    def ethertype_name(self) -> str:
        return {
            ETHERTYPE_IPV4: "IPv4",
            ETHERTYPE_IPV6: "IPv6",
            ETHERTYPE_ARP: "ARP",
        }.get(self.ethertype, f"0x{self.ethertype:04x}")


@dataclass
class IPv4:
    version: int
    header_length: int
    ttl: int
    protocol: int
    source: str
    destination: str
    total_length: int
    payload: bytes

    @property
    def protocol_name(self) -> str:
        return PROTOCOL_NAMES.get(self.protocol, str(self.protocol))


@dataclass
class IPv6:
    version: int
    next_header: int
    hop_limit: int
    source: str
    destination: str
    payload_length: int
    payload: bytes

    @property
    def protocol_name(self) -> str:
        return PROTOCOL_NAMES.get(self.next_header, str(self.next_header))


@dataclass
class TCP:
    source_port: int
    destination_port: int
    sequence: int
    acknowledgement: int
    flags: int
    window: int
    payload: bytes

    @property
    def flag_names(self) -> list[str]:
        return [name for bit, name in TCP_FLAGS if self.flags & bit]


@dataclass
class UDP:
    source_port: int
    destination_port: int
    length: int
    payload: bytes


@dataclass
class ICMP:
    type: int
    code: int
    payload: bytes


@dataclass
class Packet:
    """A decoded packet, as deep as the decoder could go."""

    link: Ethernet | None = None
    network: IPv4 | IPv6 | None = None
    transport: TCP | UDP | ICMP | None = None
    notes: list[str] = field(default_factory=list)


def format_mac(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


def format_ipv4(raw: bytes) -> str:
    return ".".join(str(byte) for byte in raw)


def format_ipv6(raw: bytes) -> str:
    groups = [raw[index : index + 2].hex() for index in range(0, 16, 2)]
    trimmed = [group.lstrip("0") or "0" for group in groups]
    return ":".join(trimmed)


def decode_ethernet(data: bytes) -> Ethernet:
    if len(data) < 14:
        raise DecodeError("Ethernet frame shorter than 14 bytes")
    destination, source, ethertype = struct.unpack(">6s6sH", data[:14])
    return Ethernet(
        destination=format_mac(destination),
        source=format_mac(source),
        ethertype=ethertype,
        payload=data[14:],
    )


def decode_ipv4(data: bytes) -> IPv4:
    if len(data) < 20:
        raise DecodeError("IPv4 header shorter than 20 bytes")

    version_ihl = data[0]
    version = version_ihl >> 4
    # The header length field counts 32-bit words, so multiply by four.
    header_length = (version_ihl & 0x0F) * 4
    if header_length < 20 or len(data) < header_length:
        raise DecodeError(f"IPv4 header length {header_length} is invalid")

    total_length = struct.unpack(">H", data[2:4])[0]
    ttl = data[8]
    protocol = data[9]
    source = format_ipv4(data[12:16])
    destination = format_ipv4(data[16:20])

    return IPv4(
        version=version,
        header_length=header_length,
        ttl=ttl,
        protocol=protocol,
        source=source,
        destination=destination,
        total_length=total_length,
        payload=data[header_length:],
    )


def decode_ipv6(data: bytes) -> IPv6:
    if len(data) < 40:
        raise DecodeError("IPv6 header shorter than 40 bytes")

    version = data[0] >> 4
    payload_length, next_header, hop_limit = struct.unpack(">HBB", data[4:8])
    source = format_ipv6(data[8:24])
    destination = format_ipv6(data[24:40])

    return IPv6(
        version=version,
        next_header=next_header,
        hop_limit=hop_limit,
        source=source,
        destination=destination,
        payload_length=payload_length,
        payload=data[40:],
    )


def decode_tcp(data: bytes) -> TCP:
    if len(data) < 20:
        raise DecodeError("TCP header shorter than 20 bytes")

    source_port, destination_port, sequence, acknowledgement = struct.unpack(">HHII", data[:12])
    data_offset_flags = struct.unpack(">H", data[12:14])[0]
    # The top 4 bits are the data offset in 32-bit words.
    header_length = (data_offset_flags >> 12) * 4
    flags = data_offset_flags & 0x01FF
    window = struct.unpack(">H", data[14:16])[0]
    payload = data[header_length:] if header_length <= len(data) else b""

    return TCP(
        source_port=source_port,
        destination_port=destination_port,
        sequence=sequence,
        acknowledgement=acknowledgement,
        flags=flags,
        window=window,
        payload=payload,
    )


def decode_udp(data: bytes) -> UDP:
    if len(data) < 8:
        raise DecodeError("UDP header shorter than 8 bytes")
    source_port, destination_port, length = struct.unpack(">HHH", data[:6])
    return UDP(
        source_port=source_port,
        destination_port=destination_port,
        length=length,
        payload=data[8:],
    )


def decode_icmp(data: bytes) -> ICMP:
    if len(data) < 4:
        raise DecodeError("ICMP header shorter than 4 bytes")
    return ICMP(type=data[0], code=data[1], payload=data[4:])


def decode_transport(protocol: int, payload: bytes) -> TCP | UDP | ICMP | None:
    try:
        if protocol == PROTO_TCP:
            return decode_tcp(payload)
        if protocol == PROTO_UDP:
            return decode_udp(payload)
        if protocol in (PROTO_ICMP, PROTO_ICMPV6):
            return decode_icmp(payload)
    except DecodeError:
        return None
    return None


def decode_packet(data: bytes, *, link_layer: bool = True) -> Packet:
    """Decode a frame as far as the transport layer.

    ``link_layer`` says whether the buffer begins with an Ethernet header. Linux
    AF_PACKET captures include it; a raw IP socket on Windows does not.
    """
    packet = Packet()
    network_bytes = data

    if link_layer:
        try:
            packet.link = decode_ethernet(data)
        except DecodeError as exc:
            packet.notes.append(str(exc))
            return packet
        if packet.link.ethertype == ETHERTYPE_IPV4:
            network_bytes = packet.link.payload
        elif packet.link.ethertype == ETHERTYPE_IPV6:
            network_bytes = packet.link.payload
        else:
            packet.notes.append(f"Unsupported ethertype {packet.link.ethertype_name}")
            return packet

    if not network_bytes:
        return packet

    version = network_bytes[0] >> 4
    try:
        if version == 4:
            packet.network = decode_ipv4(network_bytes)
            packet.transport = decode_transport(packet.network.protocol, packet.network.payload)
        elif version == 6:
            packet.network = decode_ipv6(network_bytes)
            packet.transport = decode_transport(packet.network.next_header, packet.network.payload)
        else:
            packet.notes.append(f"Unsupported IP version {version}")
    except DecodeError as exc:
        packet.notes.append(str(exc))

    return packet


def summarise(packet: Packet) -> str:
    """One readable line describing a decoded packet."""
    network = packet.network
    if network is None:
        return "non-IP frame" + (f" ({packet.notes[0]})" if packet.notes else "")

    source = network.source
    destination = network.destination
    transport = packet.transport

    if isinstance(transport, TCP):
        flags = ",".join(transport.flag_names) or "none"
        return (
            f"TCP  {source}:{transport.source_port} -> "
            f"{destination}:{transport.destination_port}  "
            f"[{flags}] seq={transport.sequence} win={transport.window} "
            f"len={len(transport.payload)}"
        )
    if isinstance(transport, UDP):
        return (
            f"UDP  {source}:{transport.source_port} -> "
            f"{destination}:{transport.destination_port}  len={len(transport.payload)}"
        )
    if isinstance(transport, ICMP):
        return f"ICMP {source} -> {destination}  type={transport.type} code={transport.code}"

    return f"{network.protocol_name} {source} -> {destination}"

"""DNS message construction and parsing, built from the wire format up.

`socket.gethostbyname` hides all of this behind one call. The point here is that
a DNS query is a specific sequence of bytes, and knowing that sequence is what
makes a zone transfer or a spoofed reply comprehensible.

Everything follows RFC 1035.
"""

from __future__ import annotations

import random
import struct
from dataclasses import dataclass, field

# Record types, from the registry in RFC 1035 and its successors.
RECORD_TYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "CAA": 257,
    "AXFR": 252,
    "ANY": 255,
}

TYPE_NAMES = {number: name for name, number in RECORD_TYPES.items()}

CLASS_IN = 1

# The RCODE field of a response header.
RESPONSE_CODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

# A compression pointer is marked by the top two bits of a length byte.
POINTER_MASK = 0xC0
MAX_POINTER_HOPS = 64


class DNSError(ValueError):
    """Raised when a DNS message cannot be built or parsed."""


@dataclass
class Record:
    name: str
    type: str
    ttl: int
    value: str


@dataclass
class Response:
    transaction_id: int
    response_code: str
    authoritative: bool
    truncated: bool
    questions: list[str] = field(default_factory=list)
    answers: list[Record] = field(default_factory=list)
    authority: list[Record] = field(default_factory=list)
    additional: list[Record] = field(default_factory=list)

    @property
    def all_records(self) -> list[Record]:
        return self.answers + self.authority + self.additional


def encode_name(name: str) -> bytes:
    """Encode a domain name as length-prefixed labels ending in a zero byte.

    ``example.com`` becomes ``\\x07example\\x03com\\x00``. There are no dots on
    the wire; the dots in the text form are only separators for the labels.
    """
    encoded = bytearray()
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("idna") if not label.isascii() else label.encode("ascii")
        if len(raw) > 63:
            raise DNSError(f"Label {label!r} exceeds the 63-byte limit")
        encoded.append(len(raw))
        encoded.extend(raw)
    encoded.append(0)
    if len(encoded) > 255:
        raise DNSError(f"Name {name!r} exceeds the 255-byte limit")
    return bytes(encoded)


def decode_name(message: bytes, offset: int) -> tuple[str, int]:
    """Decode a name, following compression pointers.

    A label length byte whose top two bits are set is not a length at all. It is
    the start of a 14-bit offset pointing elsewhere in the message, which is how
    DNS avoids repeating the same suffix in every record.
    """
    labels: list[str] = []
    hops = 0
    cursor = offset
    end_of_name: int | None = None

    while True:
        if cursor >= len(message):
            raise DNSError("Name runs past the end of the message")

        length = message[cursor]

        if length & POINTER_MASK == POINTER_MASK:
            if cursor + 1 >= len(message):
                raise DNSError("Truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | message[cursor + 1]
            # The name continues after the pointer, not after what it targets.
            if end_of_name is None:
                end_of_name = cursor + 2
            hops += 1
            if hops > MAX_POINTER_HOPS:
                raise DNSError("Compression pointer loop")
            cursor = pointer
            continue

        if length == 0:
            if end_of_name is None:
                end_of_name = cursor + 1
            break

        cursor += 1
        if cursor + length > len(message):
            raise DNSError("Label runs past the end of the message")
        labels.append(message[cursor : cursor + length].decode("ascii", errors="replace"))
        cursor += length

    return ".".join(labels), end_of_name


def build_query(name: str, record_type: str, *, transaction_id: int | None = None) -> bytes:
    """Build a standard recursive query for one name and type."""
    if record_type not in RECORD_TYPES:
        raise DNSError(f"Unknown record type {record_type!r}")

    identifier = transaction_id if transaction_id is not None else random.randint(0, 0xFFFF)
    # Flags: standard query, recursion desired.
    flags = 0x0100
    header = struct.pack(">HHHHHH", identifier, flags, 1, 0, 0, 0)
    question = encode_name(name) + struct.pack(">HH", RECORD_TYPES[record_type], CLASS_IN)
    return header + question


def _decode_record_value(
    message: bytes, record_type: int, offset: int, length: int
) -> str:
    data = message[offset : offset + length]

    if record_type == RECORD_TYPES["A"] and length == 4:
        return ".".join(str(byte) for byte in data)

    if record_type == RECORD_TYPES["AAAA"] and length == 16:
        groups = [data[index : index + 2].hex() for index in range(0, 16, 2)]
        return ":".join(group.lstrip("0") or "0" for group in groups)

    if record_type in (RECORD_TYPES["NS"], RECORD_TYPES["CNAME"], RECORD_TYPES["PTR"]):
        name, _ = decode_name(message, offset)
        return name

    if record_type == RECORD_TYPES["MX"] and length >= 3:
        (preference,) = struct.unpack(">H", data[:2])
        exchange, _ = decode_name(message, offset + 2)
        return f"{preference} {exchange}"

    if record_type == RECORD_TYPES["TXT"]:
        # TXT is a sequence of length-prefixed strings, not one blob.
        parts = []
        cursor = 0
        while cursor < length:
            size = data[cursor]
            parts.append(data[cursor + 1 : cursor + 1 + size].decode("utf-8", errors="replace"))
            cursor += 1 + size
        return "".join(parts)

    if record_type == RECORD_TYPES["SOA"]:
        primary, cursor = decode_name(message, offset)
        mailbox, cursor = decode_name(message, cursor)
        if cursor + 20 <= len(message):
            serial, refresh, retry, expire, minimum = struct.unpack(
                ">IIIII", message[cursor : cursor + 20]
            )
            return f"{primary} {mailbox} {serial} {refresh} {retry} {expire} {minimum}"
        return f"{primary} {mailbox}"

    if record_type == RECORD_TYPES["SRV"] and length >= 7:
        priority, weight, port = struct.unpack(">HHH", data[:6])
        target, _ = decode_name(message, offset + 6)
        return f"{priority} {weight} {port} {target}"

    if record_type == RECORD_TYPES["CAA"] and length >= 2:
        tag_length = data[1]
        tag = data[2 : 2 + tag_length].decode("ascii", errors="replace")
        value = data[2 + tag_length :].decode("ascii", errors="replace")
        return f"{tag} {value}"

    return data.hex()


def _parse_records(message: bytes, offset: int, count: int) -> tuple[list[Record], int]:
    records: list[Record] = []
    for _ in range(count):
        name, offset = decode_name(message, offset)
        if offset + 10 > len(message):
            raise DNSError("Record header runs past the end of the message")
        record_type, _record_class, ttl, length = struct.unpack(
            ">HHIH", message[offset : offset + 10]
        )
        offset += 10
        if offset + length > len(message):
            raise DNSError("Record data runs past the end of the message")
        value = _decode_record_value(message, record_type, offset, length)
        records.append(
            Record(
                name=name,
                type=TYPE_NAMES.get(record_type, str(record_type)),
                ttl=ttl,
                value=value,
            )
        )
        offset += length
    return records, offset


def parse_response(message: bytes) -> Response:
    """Parse a DNS response message into its four sections."""
    if len(message) < 12:
        raise DNSError("Message is shorter than a DNS header")

    identifier, flags, question_count, answer_count, authority_count, additional_count = (
        struct.unpack(">HHHHHH", message[:12])
    )

    offset = 12
    questions: list[str] = []
    for _ in range(question_count):
        name, offset = decode_name(message, offset)
        offset += 4  # QTYPE and QCLASS
        questions.append(name)

    answers, offset = _parse_records(message, offset, answer_count)
    authority, offset = _parse_records(message, offset, authority_count)
    additional, offset = _parse_records(message, offset, additional_count)

    return Response(
        transaction_id=identifier,
        response_code=RESPONSE_CODES.get(flags & 0x000F, str(flags & 0x000F)),
        authoritative=bool(flags & 0x0400),
        truncated=bool(flags & 0x0200),
        questions=questions,
        answers=answers,
        authority=authority,
        additional=additional,
    )

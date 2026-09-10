"""A minimal DER/ASN.1 reader, enough to take an X.509 certificate apart.

Written by hand rather than with a library, because the point is to see what a
certificate actually is: a nested tree of tag-length-value records. Everything
here works on the raw DER bytes a TLS handshake hands over.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

# ASN.1 universal tags used by X.509.
TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_OID = 0x06
TAG_UTF8_STRING = 0x0C
TAG_PRINTABLE_STRING = 0x13
TAG_IA5_STRING = 0x16
TAG_UTC_TIME = 0x17
TAG_GENERALIZED_TIME = 0x18
TAG_SEQUENCE = 0x30
TAG_SET = 0x31

# Context-specific tags inside TBSCertificate and GeneralName.
TAG_VERSION = 0xA0
TAG_EXTENSIONS = 0xA3
TAG_GENERALNAME_DNS = 0x82
TAG_GENERALNAME_IP = 0x87

OID_SAN = "2.5.29.17"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_KEY_USAGE = "2.5.29.15"

ATTRIBUTE_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "1.2.840.113549.1.9.1": "emailAddress",
}

SIGNATURE_ALGORITHMS = {
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.112": "Ed25519",
}

# Signature algorithms no longer fit for purpose. SHA-1 collisions are
# practical, and MD5 has been broken for far longer.
WEAK_SIGNATURE_ALGORITHMS = {
    "md5WithRSAEncryption",
    "sha1WithRSAEncryption",
    "ecdsa-with-SHA1",
}

PUBLIC_KEY_ALGORITHMS = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.10045.2.1": "EC",
    "1.3.101.112": "Ed25519",
}

EC_CURVES = {
    "1.2.840.10045.3.1.7": ("prime256v1", 256),
    "1.3.132.0.34": ("secp384r1", 384),
    "1.3.132.0.35": ("secp521r1", 521),
}


class DERError(ValueError):
    """Raised when a byte sequence is not valid DER, or not a certificate."""


@dataclass
class Node:
    """One tag-length-value record, plus where it sat in its parent."""

    tag: int
    value: bytes
    end: int

    @property
    def is_constructed(self) -> bool:
        return bool(self.tag & 0x20)


def read_node(data: bytes, offset: int = 0) -> Node:
    """Read one TLV record starting at ``offset``."""
    if offset >= len(data):
        raise DERError("Truncated: no tag byte")

    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise DERError("Multi-byte tags are not supported")

    index = offset + 1
    if index >= len(data):
        raise DERError("Truncated: no length byte")

    first_length_byte = data[index]
    index += 1
    if first_length_byte < 0x80:
        # Short form: the byte is the length.
        length = first_length_byte
    else:
        # Long form: the low 7 bits say how many bytes hold the length.
        count = first_length_byte & 0x7F
        if count == 0:
            raise DERError("Indefinite length is not allowed in DER")
        if index + count > len(data):
            raise DERError("Truncated length field")
        length = int.from_bytes(data[index : index + count], "big")
        index += count

    end = index + length
    if end > len(data):
        raise DERError("Truncated value")
    return Node(tag=tag, value=data[index:end], end=end)


def read_children(node: Node) -> list[Node]:
    """Split a constructed node into the records it contains."""
    children: list[Node] = []
    offset = 0
    while offset < len(node.value):
        child = read_node(node.value, offset)
        children.append(child)
        offset = child.end
    return children


def decode_oid(value: bytes) -> str:
    """Decode an object identifier into dotted notation.

    The first byte packs two arcs, and every later arc is base-128 with the top
    bit set on all but the final byte.
    """
    if not value:
        raise DERError("Empty object identifier")

    parts = [str(value[0] // 40), str(value[0] % 40)]
    current = 0
    for byte in value[1:]:
        current = (current << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(current))
            current = 0
    if current:
        raise DERError("Truncated object identifier")
    return ".".join(parts)


def decode_time(node: Node) -> datetime:
    """Decode UTCTime or GeneralizedTime into an aware UTC datetime."""
    text = node.value.decode("ascii", errors="replace").strip()
    if not text.endswith("Z"):
        raise DERError(f"Unsupported time offset in {text!r}")
    body = text[:-1]

    if node.tag == TAG_UTC_TIME:
        if len(body) != 12:
            raise DERError(f"Unsupported UTCTime {text!r}")
        two_digit_year = int(body[:2])
        # RFC 5280: 00-49 means 2000-2049, 50-99 means 1950-1999.
        century = 2000 if two_digit_year < 50 else 1900
        body = f"{century + two_digit_year:04d}{body[2:]}"
    elif node.tag != TAG_GENERALIZED_TIME:
        raise DERError(f"Not a time value: tag 0x{node.tag:02x}")

    if len(body) != 14:
        raise DERError(f"Unsupported time value {text!r}")
    return datetime.strptime(body, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)


def decode_name(node: Node) -> dict[str, str]:
    """Decode an X.501 Name into a mapping like ``{'CN': 'example.com'}``."""
    attributes: dict[str, str] = {}
    for relative_name in read_children(node):
        for pair in read_children(relative_name):
            fields = read_children(pair)
            if len(fields) != 2:
                continue
            oid = decode_oid(fields[0].value)
            label = ATTRIBUTE_NAMES.get(oid, oid)
            text = fields[1].value.decode("utf-8", errors="replace")
            attributes[label] = f"{attributes[label]}, {text}" if label in attributes else text
    return attributes


def _decode_public_key(spki: Node) -> tuple[str, int | None, str | None]:
    """Return the key algorithm, its size in bits, and the curve if any."""
    children = read_children(spki)
    if len(children) != 2:
        return ("unknown", None, None)

    algorithm_fields = read_children(children[0])
    if not algorithm_fields:
        return ("unknown", None, None)

    algorithm_oid = decode_oid(algorithm_fields[0].value)
    algorithm = PUBLIC_KEY_ALGORITHMS.get(algorithm_oid, algorithm_oid)

    if algorithm == "EC" and len(algorithm_fields) > 1:
        curve_oid = decode_oid(algorithm_fields[1].value)
        curve, bits = EC_CURVES.get(curve_oid, (curve_oid, None))
        return (algorithm, bits, curve)

    if algorithm == "RSA":
        # A BIT STRING starts with a count of unused trailing bits, which is
        # zero here, and the rest is the DER of RSAPublicKey.
        key_bytes = children[1].value[1:]
        try:
            key_sequence = read_node(key_bytes)
            modulus = read_children(key_sequence)[0]
        except (DERError, IndexError):
            return (algorithm, None, None)
        # Strip the leading zero DER adds to keep the integer positive.
        modulus_bytes = modulus.value.lstrip(b"\x00")
        return (algorithm, len(modulus_bytes) * 8, None)

    if algorithm == "Ed25519":
        return (algorithm, 256, None)

    return (algorithm, None, None)


def _decode_alt_names(extension_value: bytes) -> tuple[list[str], list[str]]:
    """Pull DNS names and IP addresses out of a subjectAltName extension."""
    dns_names: list[str] = []
    ip_addresses: list[str] = []
    names = read_node(extension_value)
    for entry in read_children(names):
        if entry.tag == TAG_GENERALNAME_DNS:
            dns_names.append(entry.value.decode("utf-8", errors="replace"))
        elif entry.tag == TAG_GENERALNAME_IP:
            if len(entry.value) == 4:
                ip_addresses.append(".".join(str(byte) for byte in entry.value))
            elif len(entry.value) == 16:
                groups = [entry.value[i : i + 2].hex() for i in range(0, 16, 2)]
                ip_addresses.append(":".join(groups))
    return dns_names, ip_addresses


def _decode_extensions(node: Node) -> tuple[list[str], list[str], bool | None]:
    dns_names: list[str] = []
    ip_addresses: list[str] = []
    is_ca: bool | None = None

    extensions_sequence = read_children(node)
    if not extensions_sequence:
        return dns_names, ip_addresses, is_ca

    for extension in read_children(extensions_sequence[0]):
        fields = read_children(extension)
        if not fields:
            continue
        oid = decode_oid(fields[0].value)
        # An optional critical BOOLEAN may sit between the OID and the value.
        payload = fields[-1].value

        if oid == OID_SAN:
            dns_names, ip_addresses = _decode_alt_names(payload)
        elif oid == OID_BASIC_CONSTRAINTS:
            constraints = read_children(read_node(payload))
            is_ca = bool(constraints and constraints[0].tag == TAG_BOOLEAN
                         and constraints[0].value not in (b"\x00", b""))

    return dns_names, ip_addresses, is_ca


@dataclass
class Certificate:
    """The fields of an X.509 certificate this tool cares about."""

    version: int
    serial_number: int
    issuer: dict[str, str]
    subject: dict[str, str]
    not_before: datetime
    not_after: datetime
    signature_algorithm: str
    public_key_algorithm: str
    public_key_bits: int | None = None
    public_key_curve: str | None = None
    dns_names: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    is_ca: bool | None = None

    @property
    def is_self_signed(self) -> bool:
        return self.issuer == self.subject

    @property
    def common_name(self) -> str | None:
        return self.subject.get("CN")

    @property
    def issuer_name(self) -> str:
        return self.issuer.get("CN") or self.issuer.get("O") or "unknown"

    @property
    def has_weak_signature(self) -> bool:
        return self.signature_algorithm in WEAK_SIGNATURE_ALGORITHMS

    def days_until_expiry(self, now: datetime | None = None) -> int:
        reference = now or datetime.now(timezone.utc)
        return (self.not_after - reference).days

    def is_expired(self, now: datetime | None = None) -> bool:
        reference = now or datetime.now(timezone.utc)
        return reference > self.not_after

    def is_not_yet_valid(self, now: datetime | None = None) -> bool:
        reference = now or datetime.now(timezone.utc)
        return reference < self.not_before

    def all_names(self) -> list[str]:
        names = list(self.dns_names)
        if self.common_name and self.common_name not in names:
            names.insert(0, self.common_name)
        return names


def parse_certificate(der: bytes) -> Certificate:
    """Parse DER-encoded certificate bytes into a :class:`Certificate`."""
    certificate = read_node(der)
    if certificate.tag != TAG_SEQUENCE:
        raise DERError("Certificate must be a SEQUENCE")

    top_level = read_children(certificate)
    if len(top_level) < 3:
        raise DERError("Certificate must hold tbsCertificate, algorithm and signature")

    tbs_fields = read_children(top_level[0])
    signature_fields = read_children(top_level[1])
    signature_oid = decode_oid(signature_fields[0].value) if signature_fields else ""
    signature_algorithm = SIGNATURE_ALGORITHMS.get(signature_oid, signature_oid)

    index = 0
    version = 1
    if tbs_fields and tbs_fields[0].tag == TAG_VERSION:
        inner = read_children(tbs_fields[0])
        if inner:
            version = int.from_bytes(inner[0].value, "big") + 1
        index = 1

    if len(tbs_fields) < index + 6:
        raise DERError("TBSCertificate is missing required fields")

    serial_number = int.from_bytes(tbs_fields[index].value, "big")
    issuer = decode_name(tbs_fields[index + 2])
    validity = read_children(tbs_fields[index + 3])
    if len(validity) != 2:
        raise DERError("Validity must hold notBefore and notAfter")
    subject = decode_name(tbs_fields[index + 4])
    algorithm, bits, curve = _decode_public_key(tbs_fields[index + 5])

    dns_names: list[str] = []
    ip_addresses: list[str] = []
    is_ca: bool | None = None
    for node in tbs_fields[index + 6 :]:
        if node.tag == TAG_EXTENSIONS:
            dns_names, ip_addresses, is_ca = _decode_extensions(node)

    return Certificate(
        version=version,
        serial_number=serial_number,
        issuer=issuer,
        subject=subject,
        not_before=decode_time(validity[0]),
        not_after=decode_time(validity[1]),
        signature_algorithm=signature_algorithm,
        public_key_algorithm=algorithm,
        public_key_bits=bits,
        public_key_curve=curve,
        dns_names=dns_names,
        ip_addresses=ip_addresses,
        is_ca=is_ca,
    )

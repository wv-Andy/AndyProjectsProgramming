"""IPv4 subnet calculator, built on raw bit manipulation.

Python ships `ipaddress`, which does all of this. The arithmetic here is written
out deliberately: an address is a 32-bit integer, a mask is a run of ones, and
every routing decision reduces to an AND. Seeing that once is worth more than
importing it.

The test suite checks these results against `ipaddress` to prove the maths.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterator, Sequence
from dataclasses import dataclass

ADDRESS_BITS = 32
ALL_ONES = 0xFFFFFFFF

# Private ranges from RFC 1918, plus the ones people meet in practice.
SPECIAL_RANGES = (
    ("10.0.0.0", 8, "private (RFC 1918)"),
    ("172.16.0.0", 12, "private (RFC 1918)"),
    ("192.168.0.0", 16, "private (RFC 1918)"),
    ("127.0.0.0", 8, "loopback"),
    ("169.254.0.0", 16, "link-local (APIPA)"),
    ("100.64.0.0", 10, "carrier-grade NAT"),
    ("224.0.0.0", 4, "multicast"),
    ("0.0.0.0", 8, "this network"),
)


class SubnetError(ValueError):
    """Raised when an address or prefix cannot be parsed."""


def address_to_int(text: str) -> int:
    """Turn dotted-quad notation into the 32-bit integer it stands for."""
    parts = text.strip().split(".")
    if len(parts) != 4:
        raise SubnetError(f"{text!r} is not a dotted-quad address")

    value = 0
    for part in parts:
        if not part.isdigit():
            raise SubnetError(f"{text!r} contains a non-numeric octet")
        octet = int(part)
        if not 0 <= octet <= 255:
            raise SubnetError(f"Octet {octet} in {text!r} is outside 0-255")
        # Shift the accumulator left one octet and drop the new one in.
        value = (value << 8) | octet
    return value


def int_to_address(value: int) -> str:
    """Turn a 32-bit integer back into dotted-quad notation."""
    if not 0 <= value <= ALL_ONES:
        raise SubnetError(f"{value} is outside the 32-bit address space")
    return ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def prefix_to_mask(prefix: int) -> int:
    """Build a mask of `prefix` ones followed by zeros."""
    if not 0 <= prefix <= ADDRESS_BITS:
        raise SubnetError(f"Prefix /{prefix} is outside /0-/32")
    if prefix == 0:
        return 0
    return (ALL_ONES << (ADDRESS_BITS - prefix)) & ALL_ONES


def mask_to_prefix(mask: int) -> int:
    """Count the leading ones in a mask, rejecting non-contiguous masks."""
    prefix = 0
    seen_zero = False
    for shift in range(ADDRESS_BITS - 1, -1, -1):
        bit = (mask >> shift) & 1
        if bit:
            if seen_zero:
                raise SubnetError("Mask is not contiguous, so it is not a valid CIDR prefix")
            prefix += 1
        else:
            seen_zero = True
    return prefix


def parse_prefix(text: str) -> int:
    """Accept either /24 style or a dotted-quad mask."""
    text = text.strip().lstrip("/")
    if "." in text:
        return mask_to_prefix(address_to_int(text))
    if not text.isdigit():
        raise SubnetError(f"{text!r} is not a prefix length or a mask")
    return int(text)


@dataclass
class Subnet:
    """A network, described by its base address and prefix length."""

    address: int
    prefix: int

    @property
    def mask(self) -> int:
        return prefix_to_mask(self.prefix)

    @property
    def wildcard(self) -> int:
        # The inverse mask, which is what access control lists use.
        return self.mask ^ ALL_ONES

    @property
    def network(self) -> int:
        # The heart of routing: AND the address with the mask.
        return self.address & self.mask

    @property
    def broadcast(self) -> int:
        return self.network | self.wildcard

    @property
    def total_addresses(self) -> int:
        return 1 << (ADDRESS_BITS - self.prefix)

    @property
    def usable_hosts(self) -> int:
        # /31 is a point-to-point link (RFC 3021) and /32 is a single host, so
        # neither one gives up two addresses to network and broadcast.
        if self.prefix >= 31:
            return self.total_addresses
        return self.total_addresses - 2

    @property
    def first_host(self) -> int:
        return self.network if self.prefix >= 31 else self.network + 1

    @property
    def last_host(self) -> int:
        return self.broadcast if self.prefix >= 31 else self.broadcast - 1

    @property
    def cidr(self) -> str:
        return f"{int_to_address(self.network)}/{self.prefix}"

    def contains(self, address: int) -> bool:
        return self.network <= address <= self.broadcast

    def overlaps(self, other: Subnet) -> bool:
        return self.network <= other.broadcast and other.network <= self.broadcast

    def split(self, new_prefix: int) -> list[Subnet]:
        """Divide this network into equal subnets of `new_prefix` length."""
        if new_prefix < self.prefix:
            raise SubnetError(
                f"/{new_prefix} is larger than /{self.prefix}, so it cannot be a subnet of it"
            )
        if new_prefix > ADDRESS_BITS:
            raise SubnetError(f"Prefix /{new_prefix} is outside /0-/32")

        step = 1 << (ADDRESS_BITS - new_prefix)
        return [
            Subnet(address=self.network + offset, prefix=new_prefix)
            for offset in range(0, self.total_addresses, step)
        ]

    def hosts(self) -> Iterator[int]:
        yield from range(self.first_host, self.last_host + 1)

    def classification(self) -> str:
        for base, prefix, label in SPECIAL_RANGES:
            candidate = Subnet(address=address_to_int(base), prefix=prefix)
            if candidate.contains(self.network):
                return label
        return "public"


def parse_network(text: str) -> Subnet:
    """Parse `192.168.1.0/24`, `192.168.1.0 255.255.255.0` or a bare address."""
    text = text.strip()
    if "/" in text:
        address_text, prefix_text = text.split("/", 1)
        return Subnet(address=address_to_int(address_text), prefix=parse_prefix(prefix_text))
    parts = text.split()
    if len(parts) == 2:
        return Subnet(address=address_to_int(parts[0]), prefix=parse_prefix(parts[1]))
    return Subnet(address=address_to_int(text), prefix=ADDRESS_BITS)


def supernet(subnets: Sequence[Subnet]) -> Subnet:
    """Find the smallest network that contains every subnet given."""
    if not subnets:
        raise SubnetError("Need at least one network to summarise")

    low = min(subnet.network for subnet in subnets)
    high = max(subnet.broadcast for subnet in subnets)

    # Widen the prefix until one network covers both ends of the range.
    for prefix in range(ADDRESS_BITS, -1, -1):
        candidate = Subnet(address=low, prefix=prefix)
        if candidate.contains(low) and candidate.contains(high):
            return candidate
    return Subnet(address=0, prefix=0)


def format_binary(value: int) -> str:
    """Render a 32-bit value as four dotted binary octets."""
    bits = f"{value:032b}"
    return ".".join(bits[index : index + 8] for index in range(0, 32, 8))


def build_report(subnet: Subnet) -> dict:
    return {
        "cidr": subnet.cidr,
        "network": int_to_address(subnet.network),
        "broadcast": int_to_address(subnet.broadcast),
        "netmask": int_to_address(subnet.mask),
        "wildcard": int_to_address(subnet.wildcard),
        "prefix": subnet.prefix,
        "first_host": int_to_address(subnet.first_host),
        "last_host": int_to_address(subnet.last_host),
        "total_addresses": subnet.total_addresses,
        "usable_hosts": subnet.usable_hosts,
        "classification": subnet.classification(),
    }


def print_report(subnet: Subnet, show_binary: bool) -> None:
    print(f"\nNetwork: {subnet.cidr}")
    print("-" * 56)
    rows = (
        ("Network address", int_to_address(subnet.network)),
        ("Broadcast address", int_to_address(subnet.broadcast)),
        ("Netmask", f"{int_to_address(subnet.mask)}  (/{subnet.prefix})"),
        ("Wildcard mask", int_to_address(subnet.wildcard)),
        ("First usable host", int_to_address(subnet.first_host)),
        ("Last usable host", int_to_address(subnet.last_host)),
        ("Total addresses", f"{subnet.total_addresses:,}"),
        ("Usable hosts", f"{subnet.usable_hosts:,}"),
        ("Classification", subnet.classification()),
    )
    width = max(len(label) for label, _ in rows) + 1
    for label, value in rows:
        print(f"{(label + ':').ljust(width)} {value}")

    if subnet.prefix >= 31:
        note = "point-to-point link" if subnet.prefix == 31 else "single host"
        print(f"\nNote: /{subnet.prefix} is a {note}, so no address is reserved.")

    if show_binary:
        print("\nBinary:")
        print(f"  Address:   {format_binary(subnet.address)}")
        print(f"  Netmask:   {format_binary(subnet.mask)}")
        print(f"  Network:   {format_binary(subnet.network)}")
        print(f"  Broadcast: {format_binary(subnet.broadcast)}")
        print("\n  The network address is the address ANDed with the netmask.")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="IPv4 subnet calculator built on raw bit arithmetic",
    )
    parser.add_argument("network", help="Network in CIDR notation, e.g. 192.168.1.0/24")
    parser.add_argument(
        "--split", type=int, metavar="PREFIX", help="Divide into subnets of this prefix length"
    )
    parser.add_argument(
        "--hosts-needed",
        type=int,
        metavar="COUNT",
        help="Pick the smallest prefix that fits this many hosts, then split",
    )
    parser.add_argument("--contains", metavar="ADDRESS", help="Test whether an address is inside")
    parser.add_argument(
        "--supernet",
        nargs="+",
        metavar="NETWORK",
        help="Summarise this network together with the ones listed here",
    )
    parser.add_argument("--binary", action="store_true", help="Show the binary arithmetic")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    return parser.parse_args(argv)


def prefix_for_hosts(hosts: int) -> int:
    """Smallest prefix whose usable host count reaches `hosts`."""
    if hosts < 1:
        raise SubnetError("Need at least one host")
    for prefix in range(ADDRESS_BITS, -1, -1):
        if Subnet(address=0, prefix=prefix).usable_hosts >= hosts:
            return prefix
    raise SubnetError(f"No IPv4 network holds {hosts} hosts")


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        subnet = parse_network(args.network)

        if args.supernet:
            others = [parse_network(text) for text in args.supernet]
            summary = supernet([subnet, *others])
            if args.json:
                print(json.dumps(build_report(summary), indent=2))
            else:
                print(f"\nSmallest network covering all {len(others) + 1} inputs: {summary.cidr}")
                print_report(summary, args.binary)
            return 0

        if args.contains:
            address = address_to_int(args.contains)
            inside = subnet.contains(address)
            print(f"{args.contains} is {'inside' if inside else 'outside'} {subnet.cidr}")
            return 0 if inside else 1

        target_prefix = args.split
        if args.hosts_needed is not None:
            target_prefix = prefix_for_hosts(args.hosts_needed)

        if target_prefix is not None:
            pieces = subnet.split(target_prefix)
            if args.json:
                print(json.dumps([build_report(piece) for piece in pieces], indent=2))
                return 0
            if args.hosts_needed is not None:
                print(
                    f"\n/{target_prefix} is the smallest prefix holding {args.hosts_needed} "
                    f"hosts ({pieces[0].usable_hosts} usable)."
                )
            print(f"\n{subnet.cidr} splits into {len(pieces)} subnets of /{target_prefix}:\n")
            shown = pieces[:64]
            for piece in shown:
                print(
                    f"  {piece.cidr:<20} "
                    f"{int_to_address(piece.first_host)} - {int_to_address(piece.last_host)}  "
                    f"({piece.usable_hosts:,} hosts)"
                )
            if len(shown) < len(pieces):
                print(f"  ... and {len(pieces) - len(shown):,} more")
            return 0

        if args.json:
            print(json.dumps(build_report(subnet), indent=2))
        else:
            print_report(subnet, args.binary)
        return 0

    except SubnetError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

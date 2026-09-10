"""Tests for the subnet calculator.

The interesting ones check the hand-written bit arithmetic against the standard
library's ``ipaddress`` module, which is the whole claim the project makes.
"""

from __future__ import annotations

import ipaddress

import pytest

CASES = [
    "192.168.1.0/24",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.1.130/26",
    "203.0.113.0/29",
    "8.8.8.8/32",
    "10.1.1.0/31",
    "0.0.0.0/0",
    "255.255.255.255/32",
]


# --- Conversions ----------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("0.0.0.0", 0),
        ("255.255.255.255", 0xFFFFFFFF),
        ("192.168.1.1", 0xC0A80101),
        ("10.0.0.1", 0x0A000001),
    ],
)
def test_address_conversion_round_trips(subnetcalc, text, value):
    assert subnetcalc.address_to_int(text) == value
    assert subnetcalc.int_to_address(value) == text


@pytest.mark.parametrize(
    "bad", ["192.168.1", "192.168.1.1.1", "192.168.1.256", "192.168.1.-1", "a.b.c.d", ""]
)
def test_address_to_int_rejects_bad_input(subnetcalc, bad):
    with pytest.raises(subnetcalc.SubnetError):
        subnetcalc.address_to_int(bad)


@pytest.mark.parametrize("prefix", range(0, 33))
def test_prefix_to_mask_matches_the_standard_library(subnetcalc, prefix):
    mine = subnetcalc.prefix_to_mask(prefix)
    theirs = int(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
    assert mine == theirs


@pytest.mark.parametrize("prefix", range(0, 33))
def test_mask_to_prefix_is_the_inverse(subnetcalc, prefix):
    assert subnetcalc.mask_to_prefix(subnetcalc.prefix_to_mask(prefix)) == prefix


def test_mask_to_prefix_rejects_a_non_contiguous_mask(subnetcalc):
    # 255.0.255.0 has a gap, so it is not expressible as a CIDR prefix.
    with pytest.raises(subnetcalc.SubnetError):
        subnetcalc.mask_to_prefix(subnetcalc.address_to_int("255.0.255.0"))


def test_prefix_to_mask_rejects_out_of_range(subnetcalc):
    with pytest.raises(subnetcalc.SubnetError):
        subnetcalc.prefix_to_mask(33)


def test_parse_prefix_accepts_both_notations(subnetcalc):
    assert subnetcalc.parse_prefix("24") == 24
    assert subnetcalc.parse_prefix("/24") == 24
    assert subnetcalc.parse_prefix("255.255.255.0") == 24


# --- Network arithmetic against ipaddress ---------------------------------


@pytest.mark.parametrize("cidr", CASES)
def test_network_and_broadcast_match_the_standard_library(subnetcalc, cidr):
    mine = subnetcalc.parse_network(cidr)
    theirs = ipaddress.IPv4Network(cidr, strict=False)
    assert subnetcalc.int_to_address(mine.network) == str(theirs.network_address)
    assert subnetcalc.int_to_address(mine.broadcast) == str(theirs.broadcast_address)
    assert subnetcalc.int_to_address(mine.mask) == str(theirs.netmask)
    assert subnetcalc.int_to_address(mine.wildcard) == str(theirs.hostmask)
    assert mine.total_addresses == theirs.num_addresses


@pytest.mark.parametrize("cidr", CASES)
def test_host_range_matches_the_standard_library(subnetcalc, cidr):
    """Compare the host range arithmetically.

    ``ipaddress.hosts()`` is a generator over every address, so materialising it
    for 0.0.0.0/0 would enumerate four billion of them. The bounds are derived
    instead.
    """
    mine = subnetcalc.parse_network(cidr)
    theirs = ipaddress.IPv4Network(cidr, strict=False)

    if theirs.prefixlen >= 31:
        expected_first = int(theirs.network_address)
        expected_last = int(theirs.broadcast_address)
    else:
        expected_first = int(theirs.network_address) + 1
        expected_last = int(theirs.broadcast_address) - 1

    assert mine.first_host == expected_first
    assert mine.last_host == expected_last
    # Spot-check the generator itself on a network small enough to walk.
    if theirs.num_addresses <= 256:
        hosts = list(theirs.hosts())
        if hosts:
            assert subnetcalc.int_to_address(mine.first_host) == str(hosts[0])
            assert subnetcalc.int_to_address(mine.last_host) == str(hosts[-1])


def test_usable_hosts_reserves_two_addresses(subnetcalc):
    assert subnetcalc.parse_network("192.168.1.0/24").usable_hosts == 254
    assert subnetcalc.parse_network("192.168.1.0/30").usable_hosts == 2


def test_slash_31_and_32_reserve_nothing(subnetcalc):
    """RFC 3021 makes /31 a point-to-point link with two usable addresses."""
    assert subnetcalc.parse_network("10.1.1.0/31").usable_hosts == 2
    assert subnetcalc.parse_network("10.1.1.1/32").usable_hosts == 1


def test_an_address_inside_a_subnet_is_normalised(subnetcalc):
    """192.168.1.130/26 belongs to the 192.168.1.128 network, not .0."""
    subnet = subnetcalc.parse_network("192.168.1.130/26")
    assert subnet.cidr == "192.168.1.128/26"


def test_contains(subnetcalc):
    subnet = subnetcalc.parse_network("192.168.1.0/24")
    assert subnet.contains(subnetcalc.address_to_int("192.168.1.1")) is True
    assert subnet.contains(subnetcalc.address_to_int("192.168.1.255")) is True
    assert subnet.contains(subnetcalc.address_to_int("192.168.2.1")) is False


def test_overlaps(subnetcalc):
    a = subnetcalc.parse_network("10.0.0.0/8")
    b = subnetcalc.parse_network("10.1.0.0/16")
    c = subnetcalc.parse_network("192.168.0.0/16")
    assert a.overlaps(b) is True
    assert a.overlaps(c) is False


# --- Splitting and summarising --------------------------------------------


def test_split_matches_the_standard_library(subnetcalc):
    mine = [piece.cidr for piece in subnetcalc.parse_network("192.168.1.0/24").split(26)]
    theirs = [str(net) for net in ipaddress.IPv4Network("192.168.1.0/24").subnets(new_prefix=26)]
    assert mine == theirs


def test_split_produces_the_expected_count(subnetcalc):
    assert len(subnetcalc.parse_network("10.0.0.0/8").split(16)) == 256


def test_split_to_the_same_prefix_returns_one_network(subnetcalc):
    pieces = subnetcalc.parse_network("192.168.1.0/24").split(24)
    assert len(pieces) == 1
    assert pieces[0].cidr == "192.168.1.0/24"


def test_split_rejects_a_larger_prefix(subnetcalc):
    with pytest.raises(subnetcalc.SubnetError):
        subnetcalc.parse_network("192.168.1.0/24").split(16)


@pytest.mark.parametrize(
    ("hosts", "prefix"),
    # A single host fits in /32, and two fit in /31 by RFC 3021. From three
    # hosts up, two addresses go to the network and the broadcast.
    [(1, 32), (2, 31), (3, 29), (50, 26), (254, 24), (300, 23), (1000, 22)],
)
def test_prefix_for_hosts(subnetcalc, hosts, prefix):
    assert subnetcalc.prefix_for_hosts(hosts) == prefix


def test_prefix_for_hosts_rejects_zero(subnetcalc):
    with pytest.raises(subnetcalc.SubnetError):
        subnetcalc.prefix_for_hosts(0)


def test_supernet_covers_every_input(subnetcalc):
    parts = [subnetcalc.parse_network(text) for text in ("192.168.0.0/24", "192.168.1.0/24")]
    summary = subnetcalc.supernet(parts)
    assert summary.cidr == "192.168.0.0/23"
    for part in parts:
        assert summary.contains(part.network)
        assert summary.contains(part.broadcast)


def test_supernet_of_distant_networks_widens_a_long_way(subnetcalc):
    parts = [subnetcalc.parse_network(text) for text in ("10.0.0.0/8", "192.168.0.0/16")]
    summary = subnetcalc.supernet(parts)
    assert summary.contains(subnetcalc.address_to_int("10.0.0.0"))
    assert summary.contains(subnetcalc.address_to_int("192.168.255.255"))


def test_supernet_needs_input(subnetcalc):
    with pytest.raises(subnetcalc.SubnetError):
        subnetcalc.supernet([])


# --- Classification and formatting ----------------------------------------


@pytest.mark.parametrize(
    ("cidr", "label"),
    [
        ("10.1.2.0/24", "private (RFC 1918)"),
        ("172.16.5.0/24", "private (RFC 1918)"),
        ("192.168.1.0/24", "private (RFC 1918)"),
        ("127.0.0.1/32", "loopback"),
        ("169.254.1.1/32", "link-local (APIPA)"),
        ("8.8.8.8/32", "public"),
        ("224.0.0.1/32", "multicast"),
    ],
)
def test_classification(subnetcalc, cidr, label):
    assert subnetcalc.parse_network(cidr).classification() == label


def test_private_classification_agrees_with_the_standard_library(subnetcalc):
    for cidr in ("10.1.2.0/24", "172.16.5.0/24", "192.168.1.0/24", "8.8.8.8/32"):
        mine = subnetcalc.parse_network(cidr).classification()
        theirs = ipaddress.IPv4Network(cidr, strict=False).is_private
        assert ("private" in mine) is theirs


def test_format_binary(subnetcalc):
    assert subnetcalc.format_binary(subnetcalc.address_to_int("255.255.255.0")) == (
        "11111111.11111111.11111111.00000000"
    )


def test_parse_network_accepts_a_space_separated_mask(subnetcalc):
    assert subnetcalc.parse_network("192.168.1.0 255.255.255.0").cidr == "192.168.1.0/24"


def test_parse_network_defaults_to_a_single_host(subnetcalc):
    assert subnetcalc.parse_network("192.168.1.1").prefix == 32


def test_cli_reports_an_invalid_network(subnetcalc):
    assert subnetcalc.main(["999.1.1.1/24"]) == 2


def test_cli_contains_sets_the_exit_code(subnetcalc):
    assert subnetcalc.main(["192.168.1.0/24", "--contains", "192.168.1.5"]) == 0
    assert subnetcalc.main(["192.168.1.0/24", "--contains", "10.0.0.1"]) == 1

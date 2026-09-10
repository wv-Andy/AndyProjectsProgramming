# Subnet Calculator

IPv4 subnet calculator built on raw bit arithmetic. No dependencies, and
deliberately no `ipaddress`.

Python already ships `ipaddress`, which does all of this. The arithmetic is
written out by hand here because an address is a 32-bit integer, a mask is a run
of ones, and every routing decision reduces to a single AND. Seeing that once is
worth more than importing it.

The test suite checks every result against `ipaddress`, which is how the maths
is proved rather than asserted.

## Features

- Network and broadcast addresses, netmask, wildcard mask and usable host range
- Splitting a network into equal subnets
- Picking the smallest prefix that fits a required host count
- Summarising several networks into their smallest common supernet
- Membership testing, with the answer in the exit code
- Classification: RFC 1918 private, loopback, link-local, CGNAT, multicast
- `--binary` shows the actual bitwise arithmetic
- Correct `/31` and `/32` handling, which most calculators get wrong

## Requirements

Python **3.10+**. Tested on Windows and Linux.

## Usage

```bash
# Any address in the network works, it gets normalised
python subnetcalc.py 192.168.1.130/26

# A dotted-quad mask is accepted too
python subnetcalc.py "192.168.1.0 255.255.255.0"

# Show the bit arithmetic
python subnetcalc.py 192.168.1.0/24 --binary

# Split into equal subnets
python subnetcalc.py 10.0.0.0/16 --split 24

# Or let it size the subnets for you
python subnetcalc.py 10.0.0.0/24 --hosts-needed 50

# Membership, with the answer in the exit code
python subnetcalc.py 192.168.1.0/24 --contains 192.168.1.55

# Smallest network covering several
python subnetcalc.py 192.168.0.0/24 --supernet 192.168.1.0/24 192.168.2.0/24

python subnetcalc.py 192.168.1.0/24 --json
```

### Options

| Flag | Description |
|---|---|
| `--split PREFIX` | Divide into subnets of this prefix length |
| `--hosts-needed COUNT` | Choose the smallest prefix that fits, then split |
| `--contains ADDRESS` | Test membership, exit `0` inside and `1` outside |
| `--supernet NETWORK...` | Summarise with the networks listed |
| `--binary` | Show the binary arithmetic |
| `--json` | Emit JSON instead of text |

Exit codes: `0` on success, `1` for `--contains` when outside, `2` on an
invalid address or prefix.

## Example output

```
$ python subnetcalc.py 192.168.1.130/26 --binary

Network: 192.168.1.128/26
--------------------------------------------------------
Network address:   192.168.1.128
Broadcast address: 192.168.1.191
Netmask:           255.255.255.192  (/26)
Wildcard mask:     0.0.0.63
First usable host: 192.168.1.129
Last usable host:  192.168.1.190
Total addresses:   64
Usable hosts:      62
Classification:    private (RFC 1918)

Binary:
  Address:   11000000.10101000.00000001.10000010
  Netmask:   11111111.11111111.11111111.11000000
  Network:   11000000.10101000.00000001.10000000
  Broadcast: 11000000.10101000.00000001.10111111

  The network address is the address ANDed with the netmask.
```

Notice the input was `.130` and the network is `.128`. The host bits get masked
away, which is exactly what a router does on every packet.

## How the arithmetic works

**An address is one integer.** `192.168.1.1` is
`(192 << 24) | (168 << 16) | (1 << 8) | 1`, or `0xC0A80101`. Four bytes, nothing
more.

**A mask is a run of ones.** `/26` means 26 ones then 6 zeros, which is
`(0xFFFFFFFF << (32 - 26)) & 0xFFFFFFFF`. Shifting left pushes zeros in from the
right, and the AND trims the overflow back to 32 bits.

**The network address is an AND.** `address & mask` clears every host bit,
leaving the network. This single operation is how a router decides whether a
destination is local or needs a gateway.

**The broadcast address is an OR.** `network | ~mask` sets every host bit. The
inverted mask is also the wildcard mask that access control lists use, which is
why the two always look like mirror images.

**Splitting is counting in steps.** Subnets of `/26` inside a `/24` sit
`2^(32-26) = 64` addresses apart, so the split walks the range in steps of 64.

## Design notes

**`/31` and `/32` are the interesting edge cases.** The usual rule subtracts two
addresses for the network and the broadcast, which gives a `/31` zero usable
hosts and a `/32` minus one. Both are wrong. RFC 3021 makes `/31` a
point-to-point link with two usable addresses, and a `/32` is a single host
route. The calculator special-cases both, and the tests pin the behaviour.

**Non-contiguous masks are rejected.** `255.0.255.0` has a gap in it, so it
cannot be written as a prefix length. `mask_to_prefix` walks the bits and raises
as soon as it sees a one after a zero, rather than silently miscounting.

## What I learned

- That subnetting is bit masking, and the dotted notation is just presentation
- Why the wildcard mask in an access control list is the netmask inverted
- The `/31` and `/32` exceptions, and the RFC that creates them
- How shifting and masking keep a value inside a fixed width
- That writing a test against `ipaddress` proves the maths better than any comment

## License

MIT, see [LICENSE](../../LICENSE).

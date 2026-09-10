# Packet Sniffer

Captures live traffic from a raw socket and decodes Ethernet, IP, TCP, UDP and
ICMP headers by hand. No dependencies, no libpcap.

The decoding is the point. A packet is just bytes in a known layout, and
[`decode.py`](decode.py) turns those bytes back into fields with `struct.unpack`,
one RFC header at a time.

## Features

- Decodes Ethernet II, IPv4, IPv6, TCP, UDP and ICMP
- Human-readable per-packet summary with TCP flags
- Filter by protocol or port
- Protocol counters at the end
- Works on Linux (AF_PACKET) and Windows (raw socket with SIO_RCVALL)
- The decoder is a pure, socket-free module, so it is fully tested

## Requirements

Python **3.10+**, and elevated privileges:

- **Linux:** run with `sudo`, or grant the capability once with
  `sudo setcap cap_net_raw+ep $(readlink -f $(which python3))`
- **Windows:** run the terminal as Administrator

## Usage

```bash
# Capture 20 packets (the default)
sudo python sniffer.py

# Capture 100
sudo python sniffer.py -c 100

# Only TCP
sudo python sniffer.py -p tcp

# Only traffic to or from port 443
sudo python sniffer.py --port 443

# Capture until Ctrl+C, with a protocol breakdown at the end
sudo python sniffer.py -c 0 -v
```

### Options

| Flag | Default | Description |
|---|---|---|
| `-c`, `--count` | `20` | Packets to capture, `0` for endless |
| `-p`, `--protocol` | none | `tcp`, `udp` or `icmp` |
| `--port` | none | Only packets to or from this port |
| `-v`, `--verbose` | off | Protocol counters at the end |

## Example output

```
Capturing 20 packet(s), tcp only. Ctrl+C to stop.

    1  TCP  192.168.1.20:54210 -> 93.184.216.34:443  [SYN] seq=1829… win=64240 len=0
    2  TCP  93.184.216.34:443 -> 192.168.1.20:54210  [SYN,ACK] seq=284… win=65535 len=0
    3  TCP  192.168.1.20:54210 -> 93.184.216.34:443  [ACK] seq=1829… win=64240 len=0
    4  TCP  192.168.1.20:54210 -> 93.184.216.34:443  [PSH,ACK] seq=1829… win=64240 len=517
```

Those four lines are a TCP handshake followed by the first TLS record: SYN,
SYN-ACK, ACK, then data. Reading that sequence off a live capture is the whole
reason to build this.

## What a packet actually is

Each layer wraps the one above it, and each header is a fixed sequence of bytes.

```
Ethernet  | dst MAC | src MAC | type |          14 bytes
  IPv4    | ver/ihl | ... | proto | src IP | dst IP | ...   20+ bytes
    TCP   | src port | dst port | seq | ack | flags | ...   20+ bytes
      data
```

Two details trip up every first attempt:

**Fields are packed inside bytes.** The IPv4 version and header length share the
first byte, four bits each. The header length counts 32-bit *words*, so the
value 5 means 20 bytes. TCP does the same with its data offset. You mask and
shift to pull them apart.

**Network byte order is big-endian.** A two-byte port on the wire has its most
significant byte first, which is why every `struct` format string here starts
with `>`. Read it the other way and port 80 becomes 20480.

## Design notes

**Capture is thin, decoding is everything.** The two platforms deliver packets
differently. Linux AF_PACKET gives full Ethernet frames; a Windows raw socket
gives IP packets with no Ethernet header. `decode_packet` takes a `link_layer`
flag and starts one layer lower when there is no Ethernet header. Nothing else
changes, and the decoder never touches a socket, which is why the tests can feed
it hand-built packets and never need root.

**Bad packets are noted, not fatal.** A truncated or unsupported frame records a
note on the `Packet` and returns what it managed to decode, so one malformed
capture never stops the sniffer.

## What I learned

- That a packet is bytes in a layout, and decoding is just `struct.unpack`
- Bit fields: how version and header length share one byte
- Endianness, and why every network integer is big-endian
- The TCP handshake and flag bits, seen on real traffic
- How raw capture differs between Linux and Windows, and why root is required

## Disclaimer

For education and authorised monitoring only. Capturing traffic on networks you
do not own or administer is illegal in most jurisdictions, and a sniffer sees
other people's data.

## License

MIT, see [LICENSE](../../LICENSE).

# DNS Enumeration Tool

Queries DNS records, attempts zone transfers, and brute-forces subdomains
concurrently. The DNS messages are built and parsed byte by byte in
[`dnsproto.py`](dnsproto.py), with no resolver library.

`socket.gethostbyname` hides all of this behind one call. Building the query
packet yourself is what makes a zone transfer or a spoofed reply make sense.

## Features

- Queries A, AAAA, NS, MX, TXT, SOA, CNAME and CAA in one pass
- Zone transfer (AXFR) attempt against every nameserver, over TCP
- Concurrent subdomain brute force with a built-in list or your own wordlist
- Wildcard detection, so a catch-all zone does not report every guess as a hit
- Hand-written message codec: name compression, all common record types
- Text or JSON output, no dependencies

## Requirements

Python **3.10+**. Tested on Windows and Linux.

## Usage

```bash
# All record types
python dnsenum.py example.com

# One record type
python dnsenum.py google.com --type MX

# Brute-force subdomains from the built-in list
python dnsenum.py example.com --brute

# Your own wordlist
python dnsenum.py example.com --brute --wordlist subdomains.txt

# Attempt a zone transfer
python dnsenum.py example.com --axfr

# Everything, through a specific resolver
python dnsenum.py example.com --brute --axfr --resolver 1.1.1.1 --json
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--resolver` | `8.8.8.8` | DNS server to query |
| `--timeout` | `3.0` | Seconds per query |
| `--concurrency` | `50` | Simultaneous queries during brute force |
| `--brute` | off | Brute-force subdomains |
| `--wordlist` | built-in | Wordlist file, one name per line |
| `--axfr` | off | Attempt a zone transfer |
| `--type` | none | Query a single record type |
| `--json` | off | Emit JSON instead of text |

## What a DNS query looks like on the wire

A query for `example.com` is a fixed 12-byte header followed by the question:

```
Header (12 bytes)
  transaction id   2 bytes   matched against the reply
  flags            2 bytes   recursion desired, response code
  counts           8 bytes   questions, answers, authority, additional

Question
  name             variable  length-prefixed labels, no dots
  type             2 bytes   A = 1, MX = 15, ...
  class            2 bytes   IN = 1
```

The name `example.com` is not stored with a dot. It becomes
`\x07example\x03com\x00`: a length, that many bytes, repeated, then a zero. The
dots you type are only separators for the labels.

## Name compression

Responses repeat names constantly. `example.com`, `www.example.com`,
`mail.example.com`. To save space, a name can end in a **pointer**: a byte with
its top two bits set, followed by an offset to where the rest of the name lives
earlier in the message.

The parser has to follow those pointers while remembering where the current name
actually ended, and it caps the number of hops so a message that points to
itself cannot spin forever. Getting this right is most of the work in a DNS
parser, and it is [tested directly](../../tests/test_dnsproto.py).

## Why a zone transfer matters

AXFR is the mechanism a secondary nameserver uses to copy a zone from the
primary. It runs over TCP, and each message is framed with a two-byte length
prefix because TCP has no message boundaries of its own.

A nameserver that answers an AXFR from anyone hands over its **entire zone**:
every host, every internal name, every service someone forgot was public. It is
a genuine finding, and it should never be allowed to arbitrary clients. The tool
reports it as such when it succeeds, and confirms the server refused when it
does not.

## Wildcard detection

Some zones answer for every possible name with a catch-all record. Against a
zone like that, a subdomain brute force reports thousands of false hits. Before
sweeping, the tool queries three names that cannot exist. Any address that comes
back is the wildcard, and guesses that resolve only to those addresses are
dropped from the results.

## Design notes

**UDP for queries, TCP for transfers.** Ordinary lookups go over UDP, one
datagram each, run concurrently with `asyncio`. AXFR needs TCP and its own
length-framed read loop, and it ends when the closing SOA record repeats.

**The codec is separate from the tool.** `dnsproto` knows the wire format and
nothing about sockets, so it can be tested entirely offline. `dnsenum` handles
the network and the reporting. The split is why the protocol tests can build a
response by hand and parse it without touching a resolver.

## What I learned

- The exact byte layout of a DNS query, header flags included
- Name compression, and why a parser has to track two positions at once
- That AXFR is trivial to attempt and genuinely dangerous to allow
- Why wildcard zones make naive subdomain brute forcing useless
- Splitting a protocol codec from the tool that uses it, so both can be tested

## Disclaimer

For education and authorised testing only. Zone transfers and brute forcing
against domains you do not control may be illegal and will be logged.

## License

MIT, see [LICENSE](../../LICENSE).

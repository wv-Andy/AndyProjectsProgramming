# TLS Certificate Inspector

Retrieves the certificate a host presents, reports who issued it, what names it
covers and when it expires, and flags anything worth worrying about.

The X.509 parsing is written by hand, on the raw DER bytes, with no third-party
library. That is the point of the project.

## Features

- Full certificate detail: subject, issuer, serial, validity, key and signature
- Subject alternative names, both DNS names and IP addresses
- Warnings for expiry, self-signed chains, weak signatures and undersized RSA keys
- Reads certificates that do **not** verify, so expired and self-signed hosts are
  explained rather than refused
- Reports the negotiated TLS version and cipher
- `--fail-on-warning` for use as a CI or monitoring check
- Text or JSON output, no dependencies

## Requirements

Python **3.10+**. Tested on Windows and Linux.

## Usage

```bash
# Port 443 is the default
python inspector.py example.com

# A different port
python inspector.py mail.example.com 993

# Expired and self-signed hosts are read, not refused
python inspector.py expired.badssl.com
python inspector.py self-signed.badssl.com

# Every name on a large certificate
python inspector.py cloudflare.com --all-names

# As a monitoring check: non-zero exit when anything is wrong
python inspector.py example.com --fail-on-warning

# Machine readable
python inspector.py example.com --json
```

### Options

| Flag | Default | Description |
|---|---|---|
| `port` | `443` | Positional, optional |
| `--timeout` | `10.0` | Seconds to wait for the connection |
| `--server-name` | target host | Hostname to send as SNI |
| `--all-names` | off | Print every name instead of the first eight |
| `--json` | off | Emit JSON instead of text |
| `--fail-on-warning` | off | Exit `1` when any warning is raised |

Exit codes: `0` on success, `1` when the host is unreachable or a warning is
raised with `--fail-on-warning`, `2` on an invalid argument.

## Example output

```
$ python inspector.py expired.badssl.com

Certificate for expired.badssl.com:443
------------------------------------------------------------
Subject:    CN=*.badssl.com, OU=Domain Control Validated
Issuer:     CN=COMODO RSA Domain Validation Secure Server CA, O=COMODO CA Limited
Serial:     4ae79549fa9abe3f100f17a478e16909
Valid from: 2015-04-09 00:00 UTC
Valid to:   2015-04-12 23:59 UTC
Expired:    4169 day(s) ago
Public key: RSA (2048 bits)
Signature:  sha256WithRSAEncryption
Negotiated: TLSv1.2 with ECDHE-RSA-AES128-GCM-SHA256
Trusted:    no

Names (2):
  *.badssl.com
  badssl.com

Warnings (2):
  [!] Expired 4169 day(s) ago, on 2015-04-12
  [!] Chain did not verify: certificate has expired
```

## What a certificate actually is

A certificate is a tree of **tag-length-value** records, encoded in DER. Every
record starts with a tag byte saying what it is, then a length, then that many
bytes of content. Constructed records hold more records inside them.

```
SEQUENCE                          the certificate
├── SEQUENCE                      tbsCertificate, the part that gets signed
│   ├── [0] INTEGER               version
│   ├── INTEGER                   serial number
│   ├── SEQUENCE                  signature algorithm
│   ├── SEQUENCE                  issuer name
│   ├── SEQUENCE                  validity: notBefore, notAfter
│   ├── SEQUENCE                  subject name
│   ├── SEQUENCE                  public key
│   └── [3] SEQUENCE              extensions, including subjectAltName
├── SEQUENCE                      signature algorithm, repeated
└── BIT STRING                    the signature itself
```

[`x509.py`](x509.py) walks that tree. `read_node` reads one record,
`read_children` splits a constructed one, and `parse_certificate` assembles the
fields into a dataclass.

## Design notes

**Fetch twice, on purpose.** A verified connection tells you the chain is
trusted but refuses to complete when it is not, which is exactly when you most
want to see the certificate. So the tool tries verified first, records the
result, and falls back to an unverified connection to read the bytes. The
verification outcome becomes a reported field rather than a fatal error.

**Lengths come in two forms.** A length byte below `0x80` *is* the length. From
`0x80` up, the low seven bits say how many following bytes hold the length. Get
this wrong and every offset after it is garbage. The indefinite form, `0x80`
exactly, is legal in BER but forbidden in DER, so the parser rejects it.

**The year pivot is 50, not 69.** `UTCTime` carries a two-digit year, and
RFC 5280 says `00`-`49` means 2000-2049 while `50`-`99` means 1950-1999.
Python's `strptime` uses a different pivot, at 69, so certificates in that
20-year window would decode a century out. The parser handles the year itself.

**The parser is checked against OpenSSL.** A test connects to a live host, parses
the certificate both with this code and with `ssl.getpeercert`, and asserts the
subject, the alternative names and the expiry date all match.

## What I learned

- What DER actually encodes, and why the length form matters so much
- How object identifiers pack arcs into base-128 with a continuation bit
- That the subject common name is legacy, and `subjectAltName` is what browsers use
- Why certificate validation and certificate *reading* have to be separate steps
- Reading a specification, RFC 5280, and turning it into working code

## Disclaimer

For education and authorised testing only.

## License

MIT, see [LICENSE](../../LICENSE).

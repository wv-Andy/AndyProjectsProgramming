# Service Enumerator

Minimal HTTP and HTTPS fingerprinting tool. It sends a single `HEAD` request and
reports the status line plus the headers that reveal the software behind a
service. No third-party dependencies.

## Features

- Plaintext HTTP and TLS, chosen automatically by port or forced with a flag
- Correct SNI handling, including targets addressed by raw IP
- `--insecure` for self-signed certificates and lab environments
- `--server-name` to probe a specific virtual host on a shared IP
- Reads until the header block is complete, not just one packet
- Text or JSON output

## Requirements

Python **3.10+**. Tested on Windows and Linux.

## Usage

```bash
# Plaintext
python enumerator.py example.com 80

# TLS is automatic on 443, 8443, 993 and other well-known ports
python enumerator.py example.com 443

# Force TLS on a non-standard port
python enumerator.py 10.0.0.5 9443 --tls --insecure

# Probe one virtual host on a shared IP
python enumerator.py 172.66.147.243 443 --server-name example.com

# Everything the server sent, as JSON
python enumerator.py example.com 443 --all-headers --json
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--timeout` | `5.0` | Seconds to wait for the connection and the reply |
| `--tls` / `--no-tls` | by port | Override the automatic scheme choice |
| `--insecure` | off | Skip certificate verification |
| `--server-name` | target host | Hostname used for SNI and the `Host` header |
| `--all-headers` | off | Print every header instead of the notable ones |
| `--json` | off | Emit JSON instead of text |

Exit codes: `0` on success, `1` when the target cannot be reached, `2` on an
invalid argument.

## Example output

```
$ python enumerator.py example.com 443
Service: HTTPS  (example.com:443)
Status:  HTTP/1.1 200 OK

Server:       cloudflare
Content-Type: text/html
Date:         Wed, 09 Sep 2026 23:55:51 GMT
```

```json
{
  "host": "example.com",
  "port": 443,
  "scheme": "https",
  "status_line": "HTTP/1.1 200 OK",
  "headers": { "Server": "cloudflare", "Content-Type": "text/html" }
}
```

## Notable headers

`Server` and `X-Powered-By` name the software and often its version.
`Location` exposes redirect targets and sometimes internal hostnames.
`Set-Cookie` hints at the framework through names like `PHPSESSID` or `JSESSIONID`.
A missing `Strict-Transport-Security` on an HTTPS service is a finding in itself.

## Design notes

**Certificates are bound to names, not addresses.** Verifying a certificate
against a bare IP cannot succeed, and passing an IP as the SNI value is invalid.
The tool detects an IP target and either refuses with an explanation or, with
`--insecure`, connects without SNI. Since most CDNs reject a handshake carrying
no SNI, the failure message points at `--server-name`, which sets the hostname
explicitly and is the flag that actually works for virtual-host probing.

**One `recv` is not a response.** TCP is a byte stream with no message
boundaries, so a single `recv(4096)` can return half a header block. Reading now
loops until the `\r\n\r\n` terminator, the peer closes, or a 64 KB cap is hit.

## What I learned

- How TLS, SNI and certificate validation actually relate to each other
- Why `recv` needs a loop, and what a framing terminator is for
- HTTP header semantics and what each one gives away
- Designing CLI flags that make the awkward cases reachable

## Disclaimer

For education and authorised testing only. Do not probe systems you do not own
or have explicit permission to test.

## License

MIT, see [LICENSE](../../LICENSE).

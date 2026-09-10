# Async Port Scanner

Asynchronous TCP port scanner written in Python with `asyncio`, built for fast
reconnaissance and readable reporting. No third-party dependencies.

## Features

- Concurrent TCP scanning with a configurable connection limit
- Port states: **OPEN**, **CLOSED** and **FILTERED**
- Banner grabbing for HTTP, SSH, SMTP, FTP and other common services
- Service name resolution from the system services database
- JSON reports with metadata, timing and a status summary
- Up-front DNS resolution, so a typo fails loudly instead of looking like a closed host
- Correct output when redirected to a file or a pipe, including on Windows

## Requirements

Python **3.10+**. Tested on Windows and Linux.

## Usage

```bash
# Common ports
python scanner.py scanme.nmap.org --top

# Explicit ports and ranges
python scanner.py 192.168.1.1 --ports 22,80,443,8000-8100

# Default range (1-1024) with tuned concurrency
python scanner.py scanme.nmap.org --concurrency 500 --timeout 2

# JSON report
python scanner.py scanme.nmap.org --top --json results.json

# Include closed ports in the output
python scanner.py 192.168.1.1 --ports 20-25 --show-all
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--ports` | none | Port list or ranges, e.g. `22,80,8000-8100` |
| `--start-port` / `--end-port` | `1` / `1024` | Range used when `--ports` is omitted |
| `--top` | off | Scan a curated list of 24 common ports |
| `--timeout` | `1.5` | Seconds to wait per port |
| `--concurrency` | `200` | Simultaneous connection attempts |
| `--show-all` | off | Print closed ports too |
| `--json` | none | Write a JSON report to this path |

Exit code `0` on success, `2` on an invalid argument or an unresolvable host.

## Example output

```
╔══════════════════════════════════════════════════
║ Async Port Scanner | Target: scanme.nmap.org (45.33.32.156)
╚══════════════════════════════════════════════════
Scanning 24 ports with concurrency=200 and timeout=1.5s

OPEN      22    ssh   | SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
OPEN      80    http  | HTTP/1.1 200 OK
FILTERED  443   https

Open: 2  Filtered: 1  Closed: 21  (1.83s)
```

### JSON report

```json
{
  "target": "scanme.nmap.org",
  "resolved_ip": "45.33.32.156",
  "scanned_at": "2026-01-15T10:30:00+00:00",
  "ports_scanned": 24,
  "duration_seconds": 1.83,
  "summary": { "open": 2, "closed": 21, "filtered": 1 },
  "results": [
    { "port": 22, "status": "open", "service": "ssh", "banner": "SSH-2.0-OpenSSH_6.6.1p1" }
  ]
}
```

Closed ports are omitted from the report unless `--show-all` is passed.

## How it works

1. The target is resolved once, up front, so a bad hostname is a clear error.
2. Every port becomes an `asyncio` task, throttled by a shared semaphore.
3. A successful `open_connection` means **open**, a timeout means **filtered**,
   and a refusal means **closed**.
4. Open ports get a small protocol-appropriate probe, and the first printable
   line of the reply becomes the banner.

### Why a connection timeout means "filtered"

A closed port sends back a TCP reset almost immediately. A port behind a firewall
that drops packets sends nothing at all, so the connection attempt just hangs.
The scanner treats that silence as *filtered*: something is there, but a device
in between is refusing to talk about it.

## Design notes

Two details are worth calling out, because both were bugs first.

**Service lookups must be guarded.** `socket.getservbyport` raises `OSError` for
any port the platform does not list, and port 1000 is one of them. An unguarded
call inside the banner grab propagated into the connection handler, which
reported the port as closed even though the connection had just succeeded. Every
lookup now goes through `lookup_service`, which returns `None` instead of raising.
A regression test in [`tests/test_scanner.py`](../../tests/test_scanner.py) binds
a real listener on an unassigned port and asserts it is reported open.

**Console encoding is not guaranteed.** The box-drawing header cannot be encoded
in Windows' cp1252 default, so redirecting output to a file used to crash the
program before it printed anything. The scanner now requests UTF-8 on stdout and
falls back to an ASCII header when the stream still cannot represent the characters.

## What I learned

- TCP port states, and why silence and refusal mean different things
- Coordinating thousands of coroutines with `asyncio.Semaphore`
- That platform APIs like `getservbyport` fail in ways worth handling
- Why exception ordering matters when `TimeoutError` subclasses `OSError`
- Writing regression tests that reproduce a bug before fixing it

## Disclaimer

For education and authorised testing only. Do not scan systems you do not own or
have explicit permission to test.

## License

MIT, see [LICENSE](../../LICENSE).

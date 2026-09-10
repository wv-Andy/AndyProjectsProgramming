# Vulnerability Scanner

Scans a host, identifies the software behind each open port, and matches those
versions against a local CVE feed. The output is a report ordered by severity.

This is the project that turns the earlier tools into components. It imports the
[async port scanner](../async-port-scanner/) directly rather than
reimplementing it, and reuses the banner-grabbing it already does.

## Features

- Port scan, service identification and CVE matching in one pass
- Reuses the port scanner project's code, not a copy of it
- Version-aware matching: a patched version does not match a fixed CVE
- Real version comparison, so `1.10` is correctly newer than `1.9`
- Severity from CVSS, with the report ordered worst-first
- Local JSON feed, editable and offline
- Non-zero exit on any critical or high finding, to gate CI
- Text or JSON output

## Requirements

Python **3.10+**. Tested on Windows and Linux. No dependencies.

## Usage

```bash
# Scan the common ports and match against the bundled feed
python vulnscan.py scanme.nmap.org --top

# Specific ports
python vulnscan.py 192.168.1.10 --ports 21,22,80,443

# Your own feed
python vulnscan.py 192.168.1.10 --top --feed my-feed.json

python vulnscan.py scanme.nmap.org --top --json
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--ports` | top ports | Ports to scan |
| `--top` | off | Scan a curated common-port list |
| `--timeout` | `2.0` | Timeout per port |
| `--concurrency` | `200` | Simultaneous connections |
| `--feed` | `feed.json` | CVE feed to match against |
| `--json` | off | Emit JSON instead of text |

Exit codes: `0` nothing critical or high, `1` a critical or high finding,
`2` on a bad argument or feed.

## Example output

```
$ python vulnscan.py scanme.nmap.org --ports 22,80

Vulnerability scan: scanme.nmap.org (45.33.32.156)
======================================================================

Open ports (2):
  22     ssh   SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
  80     http  HTTP/1.1 200 OK

Identified software (1):
  openssh 6.6  (port 22)

Vulnerabilities (1):
----------------------------------------------------------------------
  [MEDIUM] CVE-2017-15906  CVSS 5.3  (openssh 6.6, port 22)
      sftp-server in OpenSSH before 7.6 allows creating zero-length files
      in read-only mode.

Most serious: CVE-2017-15906 at CVSS 5.3.
```

That is the whole pipeline in one run: a port scan found 22 open, banner
grabbing read `OpenSSH_6.6.1p1`, the version parser reduced it to `6.6`, and the
matcher placed it below the `7.6` fix line for CVE-2017-15906.

## The pipeline

```
port scan  ──►  open ports with banners
                     │
banner parse  ──►  product + version   ("Apache/2.4.49" → apache 2.4.49)
                     │
feed match   ──►  CVEs whose range covers that version
                     │
severity sort ──►  report, worst first
```

Each stage is a small, testable function. The scanning stage is not
reimplemented; `vulnscan` adds `Cybersecurity/async-port-scanner` to the path and
calls `scanner.run_scan` directly.

## The version-matching problem

The core of the tool is deciding whether a detected version falls inside an
affected range, and it is easy to get wrong.

**String comparison is a trap.** `"1.10" < "1.9"` is true for strings, because
`1` then `0` sorts before `1` then `9`. For versions it is false: 1.10 came
after 1.9. So versions are parsed into integer tuples, `(1, 10)` against
`(1, 9)`, and compared numerically.

**Range edges are inclusive or exclusive, and it matters.** CVE-2017-15906
affects OpenSSH *before* 7.6, so 7.6 itself is fixed. The feed marks the end
exclusive, and the matcher treats 7.6 as safe while 7.5 is vulnerable. Get the
edge wrong and you either raise false alarms on patched software or miss the
last vulnerable release.

## The feed

[`feed.json`](feed.json) is a small set of real, well-known CVEs: the Apache
2.4.49 path traversal, the vsftpd 2.3.4 backdoor, the Exim RCE, and others. Each
entry names a product, a version range with inclusive or exclusive edges, a CVSS
score and a description. It is a demonstration feed, not a complete database. A
production tool would pull from the National Vulnerability Database, and the
format here maps cleanly onto NVD's CPE ranges.

## Honest limitations

A version match is a starting point, not proof. Backported security patches keep
a version string that looks vulnerable while the actual flaw is fixed, which
produces false positives. And no match means only that nothing in this feed
applied, never that the host is safe. The report says so.

## What I learned

- How to compose small tools into a pipeline instead of one monolith
- Why version comparison needs parsing, not string ordering
- That inclusive versus exclusive range edges decide real findings
- The CVSS severity bands, and how CVEs describe affected ranges
- That a version match is evidence, not a verdict, and a report should admit it

## Disclaimer

For education and authorised testing only. Scanning hosts you do not own or have
permission to test is illegal in most jurisdictions.

## License

MIT, see [LICENSE](../../LICENSE).

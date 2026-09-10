# Log Analyzer

Reads authentication or web access logs and reports what stands out:
brute-force attempts, scanning, injection payloads and error bursts.

This is the defensive half of the toolkit. The port scanner and the service
enumerator make noise. This one reads the noise somebody else made.

## Features

- Two formats: OpenSSH `auth.log` and the combined access log nginx and Apache use
- Format detection, so you rarely pass `--format`
- Brute-force detection with a sliding time window, separating automation from
  slow guessing
- Critical alert when a success follows repeated failures from the same address
- Scanning detection: not-found bursts and requests for sensitive paths
- Injection detection that URL-decodes first, including double encoding
- Server error rate, because not every anomaly is an attacker
- Reads `.gz` archives directly, streaming line by line
- Severity-ranked findings with the evidence behind each one
- `--fail-on-finding` for use in a cron job

## Requirements

Python **3.10+**. Tested on Windows and Linux. No dependencies.

## Usage

```bash
# Format is detected automatically
python analyzer.py samples/auth.log
python analyzer.py samples/access.log

# Rotated archives are read directly
python analyzer.py /var/log/auth.log.2.gz

# Syslog omits the year, so supply it for older files
python analyzer.py /var/log/auth.log.1 --year 2025

# Tune the thresholds
python analyzer.py samples/auth.log --failed-logins 3
python analyzer.py samples/access.log --not-found-burst 50

# In a cron job: non-zero exit when anything is found
python analyzer.py /var/log/auth.log --fail-on-finding --json
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--format` | `auto` | `auth`, `access` or `auto` |
| `--year` | current year | Year to assume for syslog timestamps |
| `--failed-logins` | `5` | Failures from one address before reporting |
| `--not-found-burst` | `20` | 404s from one client before reporting |
| `--top` | `10` | Entries in each top list |
| `--json` | off | Emit JSON instead of text |
| `--fail-on-finding` | off | Exit `1` when anything is reported |

Exit codes: `0` clean, `1` with `--fail-on-finding` and findings present,
`2` on a missing file or undetectable format.

## Example output

```
$ python analyzer.py samples/auth.log

Log analysis: auth.log
====================================================================
Detected format: auth

Summary
--------------------------------------------------------------------
  events: 23
  failures: 20
  successes: 3
  top offenders:
          12  203.0.113.42
           6  198.51.100.7

Findings (3)
--------------------------------------------------------------------
  [CRITICAL] compromise: 198.51.100.7 authenticated successfully as andy after 6 failures
      - A guessed password is the likeliest explanation
      - Rotate this account's credentials and check what the session did

  [HIGH] brute-force: 203.0.113.42 failed to authenticate 12 times, peaking at
                      12 attempts inside 5 minutes
      - users tried: root, admin, oracle, postgres, test
      - 11 distinct usernames, which suggests a wordlist

  [MEDIUM] brute-force: 198.51.100.7 failed to authenticate 6 times
      - users tried: andy, unknown
```

Sample logs live in [`samples/`](samples/). They are synthetic, and every
address in them comes from a range reserved for documentation.

## What the detections mean

**Rate is what separates a human from a script.** Twelve failures in
twenty-two seconds is automation. Six failures spread over three hours is
somebody who forgot their password, or an attacker deliberately staying under a
rate limit. A plain count cannot tell these apart, so a sliding window measures
the *peak* attempts inside any five-minute stretch, and only that raises the
severity to high.

**Many usernames means a wordlist.** One account failing repeatedly is a person.
Eleven different accounts from one address is a dictionary being worked through,
which is why the username count appears as evidence.

**Success after failure is the finding that matters.** Brute-force noise is
constant and mostly harmless. A successful login from an address that just
failed five times is the one line in the file worth waking somebody for, so it
is rated critical on its own.

**Not every anomaly is an attack.** A sustained 5xx rate is reported too. It
means a backend is failing, which matters just as much and is far more likely.

## Design notes

**Attackers encode, so the analyzer decodes.** A payload written as
`union%20select` never matches a search for `union select`. Every path is
decoded before matching, then decoded a second time to catch `%2520`, the
double-encoding trick used to slip past filters that decode only once.

**Files stream, they are not slurped.** `open_log` is a generator, and gzip is
handled by swapping the opener rather than decompressing to disk. A
multi-gigabyte rotated log costs no more memory than a small one.

**Thresholds are arguments, not constants.** What counts as an anomaly depends
entirely on the site. A `Thresholds` dataclass carries them, so the detection
functions stay pure and the tests can pin behaviour by passing values in.

## What I learned

- Regex against real log formats, which are messier than any specification
- That rate, not volume, is what distinguishes automated attacks
- Why syslog timestamps are a nuisance: no year, so context has to supply it
- Generators, and how they make file size stop mattering
- That a detection tool is mostly judgement, and the code is the easy part

## Disclaimer

For education and for logs you are authorised to read. Log files contain
personal data, including addresses and usernames.

## License

MIT, see [LICENSE](../../LICENSE).

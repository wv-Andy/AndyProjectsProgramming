# HTTP Security Header Auditor

Fetches a URL, grades the security headers it sends back, and explains what each
missing one leaves exposed. No dependencies.

Raw headers are data. A graded report with an explanation is a finding somebody
can act on, and turning one into the other is the point of this project.

## Features

- Six weighted checks producing a score out of 100 and a letter grade
- Validates header **values**, not just their presence, so a weak policy is caught
- Explains the concrete exposure behind every failure
- Partial credit for headers that are present but misconfigured
- Detects information disclosure through `Server` and `X-Powered-By`
- Follows redirects, with loop detection
- `--fail-under` for use as a CI gate
- Text or JSON output

## Requirements

Python **3.10+**. Tested on Windows and Linux.

## Usage

```bash
# https:// is assumed when no scheme is given
python auditor.py github.com

# An explicit URL
python auditor.py https://example.com/login

# Fail a build when the score drops below 70
python auditor.py mysite.com --fail-under 70

# A lab host with a self-signed certificate
python auditor.py https://10.0.0.5 --insecure

# See what a redirect source itself sets
python auditor.py http://example.com --no-follow

python auditor.py github.com --json
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--timeout` | `10.0` | Seconds to wait |
| `--insecure` | off | Skip certificate verification |
| `--no-follow` | off | Do not follow redirects |
| `--json` | off | Emit JSON instead of text |
| `--fail-under` | none | Exit `1` when the score is below this value |

Exit codes: `0` on success, `1` when unreachable or below `--fail-under`,
`2` on an invalid argument.

## Scoring

| Header | Weight | What it does |
|---|---|---|
| `Strict-Transport-Security` | 25 | Forces HTTPS on later visits |
| `Content-Security-Policy` | 25 | Restricts where scripts may load from |
| `X-Frame-Options` | 15 | Blocks framing, and so clickjacking |
| `X-Content-Type-Options` | 15 | Stops content-type guessing |
| `Referrer-Policy` | 10 | Limits URL leakage to other origins |
| `Permissions-Policy` | 10 | Disables unused browser features |

Grades run A at 90, B at 80, C at 70, D at 60, E at 40 and F below that.

## Example output

```
$ python auditor.py github.com

Security header audit: https://github.com
====================================================================
HTTP status: 200
Grade: C  (77/100)

[+] Strict-Transport-Security
    max-age=31536000s with includeSubDomains

[~] Content-Security-Policy
    Allows unsafe-inline, so injected scripts still run

[+] X-Frame-Options
    Set to DENY

[-] Permissions-Policy
    Missing. Embedded content can reach the camera, microphone or location

Information disclosure:
    Server: github.com

2 of 6 checks need attention.
```

`[+]` passed, `[~]` present but weak, `[-]` missing.

## Why value checks matter

Presence alone is close to meaningless, and three cases show why.

**`max-age=100` is theatre.** An HSTS policy expiring in 100 seconds protects
nobody. The check requires at least 180 days, the threshold browsers use for
preload eligibility.

**`unsafe-inline` cancels the policy.** A Content-Security-Policy exists to stop
injected scripts running. Allowing inline scripts permits exactly the thing it
was deployed to prevent, so the check fails it even though the header is there.

**HSTS over plain HTTP does nothing.** Browsers ignore the header in an HTTP
response, precisely because an attacker positioned to alter that response could
also strip it. Auditing an `http://` URL therefore scores the header zero no
matter what it says.

## Design notes

**Partial credit is deliberate.** A weak header still earns half its weight. A
site with a flawed CSP is genuinely better off than one with none, and a scoring
model that ignores that pushes people toward removing headers they cannot
perfect.

**Redirects are followed by default, and tracked.** Most sites answer `http://`
with a redirect to `https://`, and the headers that matter are on the
destination. A `seen` set catches loops rather than hitting the redirect cap.

## What I learned

- What each security header actually defends against, at the browser level
- That a misconfigured header can be worse than an absent one, because it looks solved
- How to turn scattered signals into a single number that survives a conversation
- Redirect handling, and why loop detection is not optional

## Disclaimer

For education and authorised testing only.

## License

MIT, see [LICENSE](../../LICENSE).

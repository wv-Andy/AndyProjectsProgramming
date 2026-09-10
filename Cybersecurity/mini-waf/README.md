# Mini Web Application Firewall

A reverse proxy that inspects incoming requests, blocks common attack payloads,
rate-limits each client, and logs every decision. No dependencies.

Requests hit the WAF, get scored against a set of signatures, and are either
forwarded to the backend or refused with a 403. The inspection engine is a
separate, socket-free module, which is why it is thoroughly tested.

## Features

- Signatures for SQL injection, XSS, path traversal, command injection and recon
- A scoring model: weak signals add up, one strong signal blocks
- URL-decodes twice, so encoded and double-encoded payloads are still caught
- Inspects the path, query, body and headers
- Per-client sliding-window rate limiting
- JSON decision log
- Configurable block threshold

## Requirements

Python **3.10+**. Tested on Windows and Linux.

## Usage

Run a backend, then put the WAF in front of it:

```bash
# A backend to protect, on port 8000
python -m http.server 8000

# The WAF in front, forwarding clean traffic to it
python waf.py --listen 127.0.0.1:8080 --backend http://127.0.0.1:8000

# In another terminal:
curl "http://127.0.0.1:8080/"                                  # 200, forwarded
curl "http://127.0.0.1:8080/?id=1%20UNION%20SELECT%20pw"       # 403, blocked
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--listen` | `127.0.0.1:8080` | Address the WAF listens on |
| `--backend` | `http://127.0.0.1:8000` | Where clean requests go |
| `--threshold` | `5` | Score at which a request is blocked |
| `--rate` | `100` | Max requests per client per window |
| `--window` | `10.0` | Rate-limit window in seconds |
| `--log` | stdout | Append JSON decisions to this file |

## How scoring works

Each signature carries a severity in points. A request accumulates points for
every signature it trips, and is blocked once the total reaches the threshold.

This is better than blocking on any single match. A lone backtick in a query is
suspicious but not proof, so it scores 3 and passes. A `UNION SELECT` is a clear
injection attempt, so it scores 5 and blocks on its own. Two weak signals
together can also cross the line. Tuning the threshold trades false positives
against false negatives, which is the central tradeoff of every WAF.

## Encoding evasion

The engine URL-decodes the request twice before matching. Attackers encode
payloads precisely to get past filters: `UNION SELECT` becomes
`UNION%20SELECT`, and a filter that only decodes once sees `%2520` where a `%20`
should be. Decoding twice defeats both. The tests cover single and double
encoding.

## Why this is a losing game, honestly

This is the most important thing the project teaches, and it is a limitation, not
a feature.

Signature matching blocks known payloads and automated noise. It does not stop a
determined attacker. Every signature here can be worked around: comments break up
keywords (`UN/**/ION SEL/**/ECT`), case and whitespace shift, alternate encodings
pile up, and logic can be expressed in forms no pattern anticipated. A WAF raises
the cost of an attack and cuts the noise floor. It is a layer, never the fix.

The real fix is in the application: parameterised queries stop SQL injection
outright, output encoding stops XSS, and neither depends on guessing the payload
in advance. A WAF buys time and visibility. It does not make insecure code safe.

## Design notes

**The engine never touches a socket.** All the judgement, signatures, scoring and
rate limiting, lives in [`engine.py`](engine.py) and operates on a plain
`Request` object. [`waf.py`](waf.py) is the proxy shell that turns a real HTTP
request into that object and acts on the verdict. The split is why the engine
tests run instantly and the rate limiter can be driven with a fake clock.

**The rate limiter is a sliding window.** Each client has a queue of request
timestamps. On every request, timestamps older than the window are dropped and
the new one appended; if the queue is longer than the limit, the request is
refused. No background cleanup, no fixed buckets that reset on a boundary.

## What I learned

- Writing attack signatures, and why scoring beats a single-match block
- That decoding has to happen before matching, and once is not enough
- A sliding-window rate limiter, and why it beats fixed buckets
- Building a reverse proxy with the standard library
- Above all, that pattern matching cannot win against a creative attacker, and
  why the real defence belongs in the application

## Disclaimer

For education. This is a teaching tool, not a production firewall. Do not put it
in front of anything that matters.

## License

MIT, see [LICENSE](../../LICENSE).

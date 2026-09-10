# AndyProjectsProgramming

[![CI](https://github.com/wv-Andy/AndyProjectsProgramming/actions/workflows/ci.yml/badge.svg)](https://github.com/wv-Andy/AndyProjectsProgramming/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Learning portfolio of a self-taught student preparing for a degree in **Computer
Systems Engineering**, focused on **cybersecurity**, networking and Python.

Every project here is built from scratch, documented, and tested. The point is
not to reimplement `nmap`, it is to understand what `nmap` actually does.

---

## Projects

| Project | What it does | Language | Status |
|---|---|---|---|
| [Async Port Scanner](Cybersecurity/async-port-scanner/) | Concurrent TCP port scanner with banner grabbing and JSON reports | Python | Working |
| [Service Enumerator](Cybersecurity/service-enumerator/) | HTTP/HTTPS header fingerprinting over TLS or plaintext | Python | Working |

Planned work is tracked in the [roadmap](Docs/ROADMAP.md).

---

## Repository layout

```
AndyProjectsProgramming/
├── Cybersecurity/        Security tooling and exercises
│   ├── async-port-scanner/
│   └── service-enumerator/
├── Networking/           Protocol notes and experiments
├── PythonProjects/       General-purpose Python work
├── Docs/                 Technical notes and the roadmap
├── Others/               Everything that fits nowhere else
├── tests/                Test suite for every project
└── .github/workflows/    Continuous integration
```

Each top-level folder has its own README explaining what belongs in it.

---

## Quick start

Requires **Python 3.10 or newer**. Neither tool has runtime dependencies.

```bash
git clone https://github.com/wv-Andy/AndyProjectsProgramming.git
cd AndyProjectsProgramming

# Scan a host you are allowed to test
python Cybersecurity/async-port-scanner/scanner.py scanme.nmap.org --top

# Fingerprint a web service
python Cybersecurity/service-enumerator/enumerator.py example.com 443
```

## Running the tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest
```

The suite runs entirely offline apart from two DNS lookups, and covers the
regression that used to make the scanner report open ports as closed.

---

## Skills demonstrated

- **Python**: asyncio, dataclasses, argparse, sockets, `ssl`, structured error handling
- **Networking**: TCP handshakes, port states, banner grabbing, TLS and SNI, HTTP headers
- **Tooling**: pytest, GitHub Actions, ruff, Git
- **Platforms**: Linux and Windows, including their encoding differences

## Responsible use

These tools are for education and for systems you own or have written
permission to test. Unauthorised scanning is illegal in most jurisdictions.

## License

Released under the [MIT License](LICENSE).

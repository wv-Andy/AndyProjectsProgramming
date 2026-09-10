# Cybersecurity

Security tooling written from scratch to understand how the standard tools work
underneath. Each project is a self-contained folder with its own README.

## Projects

| Project | Description |
|---|---|
| [async-port-scanner](async-port-scanner/) | Concurrent TCP port scanner with banner grabbing and JSON reports |
| [service-enumerator](service-enumerator/) | HTTP/HTTPS header fingerprinting over TLS or plaintext |

Planned additions are listed in the [roadmap](../Docs/ROADMAP.md).

## Conventions

Every project in this folder ships with:

- a `README.md` covering usage, options, example output and what was learned
- tests in the repository-wide [`tests/`](../tests/) folder
- the standard library only, unless a dependency is genuinely unavoidable
- a disclaimer, because these are offensive-security tools

## Responsible use

Everything here is for education and for systems you own or have written
permission to test. Scanning or probing third-party infrastructure without
authorisation is illegal in most jurisdictions. `scanme.nmap.org` exists
precisely so you have a legal target to practise against.

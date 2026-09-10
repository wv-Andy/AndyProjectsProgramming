# Roadmap

Planned projects for this repository, ordered by difficulty. Each entry says
what it teaches, because a portfolio project that teaches nothing is just code.

The rule for this list: build the thing that explains a protocol, not the thing
that wraps a library. A subdomain finder that calls an API teaches an API. A
subdomain finder that builds DNS queries teaches DNS.

---

## Tier 1: done

All four are built, documented and tested. Each one closed a gap the first two
tools left open.

### 1. TLS certificate inspector — [built](../Cybersecurity/tls-inspector/)
Connect to a host, pull the certificate chain, and report issuer, subject,
alternative names, key algorithm and expiry. Flag anything expiring within 30
days, self-signed, or using a weak signature.

**Teaches:** X.509 structure, chains of trust, the `ssl` module beyond
`create_default_context`. Directly extends the service enumerator, which
currently ignores the certificate it validates.
**Folder:** `Cybersecurity/tls-inspector`

### 2. HTTP security header auditor — [built](../Cybersecurity/header-auditor/)
Fetch a site and grade its security headers: HSTS, Content-Security-Policy,
X-Frame-Options, X-Content-Type-Options, Referrer-Policy. Explain what each
missing header exposes and output a letter grade.

**Teaches:** browser security model, defensive posture, turning raw data into
a judgement. Reuses the enumerator's header parsing.
**Folder:** `Cybersecurity/header-auditor`

### 3. Subnet calculator — [built](../Networking/subnet-calculator/)
Take `192.168.1.0/24` and report network address, broadcast, usable range, host
count and mask in both notations. Add subnet splitting and a supernet mode.

**Teaches:** binary arithmetic on addresses, CIDR, the bit manipulation behind
every routing decision. Write it without `ipaddress` first, then compare.
**Folder:** `Networking/subnet-calculator`

### 4. Log parser and anomaly reporter — [built](../Cybersecurity/log-analyzer/)
Parse auth logs or web access logs. Count failed logins per IP, flag brute-force
patterns, spot scanning behaviour in 404 bursts, and summarise the top offenders.

**Teaches:** regex, generators for files too big for memory, and the defensive
half of security, which the current tools do not cover at all.
**Folder:** `Cybersecurity/log-analyzer`

---

## Tier 2: done

Multi-day projects, each with a concept that is genuinely hard the first time.

### 5. DNS enumeration tool - [built](../Networking/dns-enum/)
Query A, AAAA, MX, NS, TXT and CNAME records. Attempt a zone transfer, then
brute-force subdomains from a wordlist, concurrently.

**Teaches:** DNS record types, why `AXFR` being open is a finding, and
concurrency applied to something other than TCP connects. Build the query
packets by hand if you want the full lesson.
**Folder:** `Networking/dns-enum`

### 6. Packet sniffer - [built](../Networking/packet-sniffer/)
Capture live traffic with a raw socket, decode Ethernet, IP and TCP/UDP headers
by hand, and print a readable per-packet summary with filtering.

**Teaches:** what a packet actually *is*, byte-level parsing with `struct`,
header layouts, and endianness. Requires root or Administrator, which is a
lesson in itself.
**Folder:** `Networking/packet-sniffer`

### 7. Password strength and breach auditor - [built](../Cybersecurity/password-auditor/)
Score passwords on real entropy rather than the usual "one symbol" theatre.
Check against the Have I Been Pwned range API using k-anonymity, so the password
never leaves the machine.

**Teaches:** entropy maths, SHA-1 hashing, and the k-anonymity trick, which is
an elegant piece of privacy engineering worth understanding.
**Folder:** `Cybersecurity/password-auditor`

### 8. File integrity monitor - [built](../Cybersecurity/integrity-monitor/)
Baseline a directory tree with hashes, then detect additions, deletions and
modifications on later runs. Persist the baseline and report a clean diff.

**Teaches:** hashing at scale, state persistence, filesystem traversal, and the
core idea behind host-based intrusion detection.
**Folder:** `Cybersecurity/integrity-monitor`

---

## Tier 3: done

The portfolio centrepieces. All four are built.

### 9. Vulnerability scanner - [built](../Cybersecurity/vuln-scanner/)
Combine the port scanner and the service enumerator into one pipeline: discover
hosts, identify services and versions, match them against a local CVE feed, and
produce a prioritised report.

**Teaches:** systems integration, CVE and CPE data models, risk scoring, and
report design. This is the project that makes the earlier ones look like
components of something bigger.
**Folder:** `Cybersecurity/vuln-scanner`

### 10. Mini web application firewall - [built](../Cybersecurity/mini-waf/)
A reverse proxy that inspects requests, blocks SQL injection and XSS attempts by
pattern, rate-limits per client, and logs decisions.

**Teaches:** proxying, request parsing, attack signatures, and above all why
pattern matching is a losing game against a determined attacker.
**Folder:** `Cybersecurity/mini-waf`

### 11. Encrypted chat over sockets - [built](../Cybersecurity/secure-chat/)
A client and server exchanging keys with Diffie-Hellman and encrypting messages
with AES-GCM. Multiple clients, graceful disconnects, and no plaintext on the wire.

**Teaches:** key exchange, symmetric versus asymmetric crypto, authenticated
encryption, and socket concurrency. Prove it with a capture showing only
ciphertext.
**Folder:** `Cybersecurity/secure-chat`

### 12. CTF write-up collection - [structure built](ctf-writeups/)
Solve challenges on TryHackMe, HackTheBox or PicoCTF and document each one:
the reconnaissance, the failed attempts, the working exploit, and the fix.

**Teaches:** applied methodology, and the writing skill that turns a solved box
into evidence someone else can evaluate. Failed attempts are the valuable part.
**Folder:** `Docs/ctf-writeups`

---

## Python fundamentals

All built, to show range beyond security tooling.

| Project | Teaches | |
|---|---|---|
| File organiser by type and date | `pathlib`, safe file operations, dry-run design | [built](../PythonProjects/file-organizer/) |
| Markdown to HTML converter | Parsing, state machines, escaping | [built](../PythonProjects/markdown-converter/) |
| CLI task manager with JSON storage | Persistence, CRUD, atomic writes, argparse subcommands | [built](../PythonProjects/task-manager/) |
| Concurrent web scraper | `asyncio` reused outside networking, rate limiting, politeness | [built](../PythonProjects/web-scraper/) |
| Simple key-value database | Log-structured storage, indexing, durability | [built](../PythonProjects/kv-database/) |

---

## Status

Every project on this roadmap is built, documented and tested. What remains is
upkeep and polish, not new construction.

## Repository upkeep

- [ ] Pin the vulnerability scanner, the TLS inspector and the encrypted chat on the GitHub profile
- [ ] Add topics on GitHub: `python`, `cybersecurity`, `networking`, `asyncio`, `security-tools`
- [ ] Set the repository description and social preview image
- [x] Keep every new project covered by tests, since CI runs on each push
- [x] Record what was learned in each README while it is still fresh
- [ ] Fill in `Docs/ctf-writeups/` as challenges are solved

## Choosing what to build

Pick the project you cannot yet explain out loud. If you already know how it
works, it makes a good afternoon but a weak portfolio entry. The interesting
line in each README is "what I learned", so build things that give that section
something to say.

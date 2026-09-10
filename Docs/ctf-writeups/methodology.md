# CTF Methodology

A consistent set of phases to work a box. The value of a method is that when you
are stuck, it tells you what you have not tried yet.

## 1. Reconnaissance

Map what is there before touching anything.

- Scan for open ports and running services. The [async port
  scanner](../../Cybersecurity/async-port-scanner/) and the [vulnerability
  scanner](../../Cybersecurity/vuln-scanner/) in this repository are built for
  exactly this.
- Identify service versions from banners. A version is often the whole challenge.
- For web services, enumerate directories, read the page source, check robots.txt.
- Note everything. The detail that matters is rarely obvious at the time.

## 2. Enumeration

Turn the map into a list of things to try.

- Match service versions against known vulnerabilities.
- Look for default or weak credentials.
- Enumerate users, shares, endpoints, parameters.
- For web, test every input: forms, URL parameters, headers, cookies.

The [service enumerator](../../Cybersecurity/service-enumerator/) and the
[DNS enumeration tool](../../Networking/dns-enum/) help here.

## 3. Exploitation

Get a foothold.

- Start with the highest-value, lowest-effort finding.
- Web: injection, file upload, traversal, authentication bypass.
- Services: known CVEs, misconfigurations, exposed admin interfaces.
- Record the exact command or request that worked. You will need it for the
  write-up, and to prove the finding.

## 4. Privilege escalation

A foothold is rarely the goal; root or administrator is.

- Enumerate the system: users, running processes, scheduled tasks, sudo rights.
- Look for misconfigured permissions, writable files run as root, known kernel
  or local exploits.
- On Linux, check SUID binaries and `sudo -l`. On Windows, check service
  permissions and unquoted service paths.

## 5. Documentation

Write it up while it is fresh, in [`TEMPLATE.md`](TEMPLATE.md) form.

- What you tried that did **not** work, and why. This is the part that teaches.
- The working exploit, reproducibly, with the exact commands.
- The root cause, and how the target should have been configured to prevent it.

## A principle worth keeping

If you are stuck, you have almost always under-enumerated. The answer is usually
a service, a parameter or a file you noticed but did not follow up. Go back to
phase 1 and look harder before reaching for a more exotic exploit.

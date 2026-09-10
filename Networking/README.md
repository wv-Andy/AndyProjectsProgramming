# Networking

Notes, experiments and small tools about how networks actually behave, as
opposed to how the diagrams say they behave.

## Scope

- Protocol fundamentals: TCP/IP, UDP, DNS, HTTP, TLS
- Packet-level observation with tcpdump and Wireshark
- Routing, subnetting and address planning
- Lab setups and the results of breaking them on purpose

## Projects

| Project | Description |
|---|---|
| [subnet-calculator](subnet-calculator/) | IPv4 subnetting from raw bit arithmetic, verified against `ipaddress` |
| [dns-enum](dns-enum/) | Builds DNS packets by hand: records, zone transfers, subdomain brute force |
| [packet-sniffer](packet-sniffer/) | Decodes Ethernet, IP, TCP, UDP and ICMP headers from raw captures |

More planned work is listed in the [roadmap](../Docs/ROADMAP.md).

## Conventions

A note goes in `notes/` as Markdown. A tool gets its own folder with a README,
matching the layout used in [Cybersecurity](../Cybersecurity/). Captures and
scan output belong in the write-up that explains them, not committed as raw files.

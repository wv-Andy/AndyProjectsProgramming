\# Async Port Scanner



Asynchronous TCP port scanner built with Python using `asyncio`, designed for fast

network reconnaissance and clean, readable reporting.



---



\## Features

\- Asynchronous TCP scanning using Python `asyncio`

\- Configurable concurrency and per-port timeout

\- Port state detection: \*\*OPEN / CLOSED / FILTERED\*\*

\- Smart banner grabbing for common services (HTTP, SSH, SMTP, etc.)

\- Clean CLI output for quick analysis

\- Optional JSON export for reports or automation

\- No external dependencies



---



\## Requirements

\- Python \*\*3.10+\*\*

\- Tested on \*\*Windows\*\* and \*\*Linux\*\*



---



\## Usage



\### Basic scan

```bash

python scanner.py scanme.nmap.org



Scan common ports:

python scanner.py scanme.nmap.org --top



Custom ports

python scanner.py 192.168.1.1 --ports 22,80,443



JSON output

python scanner.py scanme.nmap.org --top --json results.json





\## Example Output

OPEN      22    ssh | SSH-2.0-OpenSSH\_8.9

OPEN      80    http | Apache

FILTERED  443   unknown



Open ports: 2





\## How it Works



Uses non-blocking TCP connections via Python asyncio



A semaphore limits concurrent connection attempts



Connection timeouts are used to infer filtered ports



Lightweight probes are sent to identify service banners





\## What I Learned



TCP connection behavior and port states



Asynchronous I/O with Python asyncio



Network service identification through banner grabbing



Designing clean CLI tools and readable output





\## Disclaimer



This tool is intended for educational purposes and authorized testing only.

Do not scan systems you do not own or have explicit permission to test.



\## License



MIT License




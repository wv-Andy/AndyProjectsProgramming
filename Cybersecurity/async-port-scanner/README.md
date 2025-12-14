# Async Port Scanner
Asynchronous TCP port scanner built with Python using `asyncio`, designed for fast
network reconnaissance and clean, readable reporting.

## Features
- Asynchronous TCP scanning using Python `asyncio`
- Configurable concurrency and per-port timeout
- Port state detection: **OPEN / CLOSED / FILTERED**
- Smart banner grabbing for common services (HTTP, SSH, SMTP, etc.)
- Clean CLI output for quick analysis
- Optional JSON export for reports or automation
- No external dependencies

## Requirements
- Python **3.10+**
- Tested on **Windows** and **Linux**

## Usage

1. Basic scan

python scanner.py scanme.nmap.org

2. Scan common ports

python scanner.py scanme.nmap.org --top

3. Custom ports

python scanner.py 192.168.1.1 --ports 22,80,443

4. JSON output

python scanner.py scanme.nmap.org --top --json results.json

Example Output

OPEN      22    ssh | SSH-2.0-OpenSSH_8.9
OPEN      80    http | Apache
FILTERED  443   unknown

Open ports: 2

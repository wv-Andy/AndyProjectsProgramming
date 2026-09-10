# File Integrity Monitor

Records a baseline of a directory tree, then detects on later runs what was
added, removed or changed. No dependencies.

This is the idea behind host-based intrusion detection. An attacker who plants a
backdoor, edits a config file or swaps a binary changes the filesystem, and a
hash of every file notices even when the timestamp was reset to hide it.

## Features

- Baselines an entire tree: content hash, size and permissions per file
- Detects added, removed and modified files on later checks
- Catches edits that keep the byte count the same, because it hashes content
- Catches permission changes, not just content
- Baseline persisted as readable JSON
- Sensible default ignores (`.git`, `__pycache__`, `node_modules`, and more)
- `--update` to accept the current state as the new baseline
- Exit code gates a cron job: non-zero when anything changed

## Requirements

Python **3.10+**. Tested on Windows and Linux.

## Usage

```bash
# Record a baseline
python fim.py init /etc --baseline etc-baseline.json

# Later, check for changes
python fim.py check /etc --baseline etc-baseline.json

# Ignore extra patterns
python fim.py init /var/www --ignore "*.log" --ignore "cache"

# Accept the current state as the new baseline
python fim.py check /etc --baseline etc-baseline.json --update

# Machine readable, for a cron job
python fim.py check /etc --baseline etc-baseline.json --json
```

Exit codes: `init` returns `0`. `check` returns `0` when clean, `1` when
anything changed, `2` on an error such as a missing baseline.

## Example output

```
$ python fim.py check /etc --baseline etc-baseline.json

Added (1):
  + cron.d/suspicious-job

Modified (2):
  ~ passwd  (content, size 2841 -> 2903)
  ~ ssh/sshd_config  (content)

Removed (1):
  - motd

4 change(s) detected.
```

## Why hash the content

A monitor could compare modification times, and many do. That is easy to defeat:
after editing a file, an attacker resets its timestamp with `touch -r`, and a
time-based check sees nothing.

A content hash cannot be fooled that way. Change one byte and the hash changes.
This tool records the SHA-256 of every file, so an edit is caught no matter what
was done to the metadata. It records size and permission bits too, which means a
file made world-writable or setuid is flagged even if its content never changed.

## Design notes

**Chunked hashing.** Files are read in 64 KiB blocks and fed to the hash
incrementally, so a multi-gigabyte file never loads into memory. The same reason
the log analyzer streams its input.

**The baseline ignores itself.** The baseline JSON usually lives inside the tree
it describes. Without care it would report itself as an added file on the first
check, then as modified after every `--update`. The tool works out the
baseline's path relative to the tree and adds it to the ignore list
automatically. This was a real bug the tests caught.

**Directory pruning.** Ignored directories are removed from the walk in place, so
`os.walk` never descends into `.git` or `node_modules` at all, rather than
walking them and discarding the results.

## What I learned

- Why content hashing beats timestamps for tamper detection
- That permission changes matter as much as content changes
- Chunked hashing, and why file size then stops mattering
- Pruning `os.walk` in place instead of filtering afterwards
- A tool that monitors a tree has to exclude its own state file, a subtlety the
  tests surfaced

## Disclaimer

For education and for systems you administer.

## License

MIT, see [LICENSE](../../LICENSE).

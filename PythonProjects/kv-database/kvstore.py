"""A tiny append-only key-value database.

This is a log-structured store, the same core idea behind Bitcask, LevelDB and
many others. It shows what a database actually is underneath the query language:
a file, an append, and an in-memory index.

How it works:

- Every write appends a record to the end of a log file. Nothing is ever
  overwritten in place, so a crash mid-write can only lose the last record, never
  corrupt an earlier one.
- An in-memory dictionary maps each key to the byte offset of its latest record.
  A read is one seek and one read, regardless of how large the log has grown.
- On startup the log is replayed to rebuild the index. The last record for a key
  wins, which is how updates and deletes work without touching old data.
- Compaction rewrites the log with only the live records, reclaiming the space
  that superseded and deleted records still occupy.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

# A sentinel written to the log to mark a key as deleted (a "tombstone").
TOMBSTONE = "\x00__deleted__\x00"


class KVError(RuntimeError):
    """Raised for store-level errors."""


class KVStore:
    """An append-only key-value store backed by a single log file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.index: dict[str, int] = {}
        self._load_index()

    def _load_index(self) -> None:
        """Replay the log to rebuild the key-to-offset index."""
        self.index.clear()
        if not self.path.exists():
            return

        offset = 0
        with self.path.open("rb") as handle:
            for line in handle:
                try:
                    record = json.loads(line)
                    key = record["key"]
                    value = record["value"]
                except (json.JSONDecodeError, KeyError, TypeError):
                    # A torn final line from an interrupted write: stop here.
                    break
                if value == TOMBSTONE:
                    self.index.pop(key, None)
                else:
                    # A later record for the same key supersedes the earlier one.
                    self.index[key] = offset
                offset += len(line)

    def _append(self, key: str, value: str) -> int:
        """Append one record and return the offset it was written at."""
        record = json.dumps({"key": key, "value": value}) + "\n"
        encoded = record.encode("utf-8")
        with self.path.open("ab") as handle:
            offset = handle.tell()
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())  # durability: survive a power loss
        return offset

    def set(self, key: str, value: str) -> None:
        if not key:
            raise KVError("Key must not be empty")
        offset = self._append(key, value)
        self.index[key] = offset

    def get(self, key: str) -> str | None:
        offset = self.index.get(key)
        if offset is None:
            return None
        with self.path.open("rb") as handle:
            handle.seek(offset)
            record = json.loads(handle.readline())
        return record["value"]

    def delete(self, key: str) -> bool:
        if key not in self.index:
            return False
        self._append(key, TOMBSTONE)
        del self.index[key]
        return True

    def keys(self) -> list[str]:
        return sorted(self.index)

    def __len__(self) -> int:
        return len(self.index)

    def __contains__(self, key: str) -> bool:
        return key in self.index

    def compact(self) -> int:
        """Rewrite the log with only live records, reclaiming dead space.

        Written to a temporary file and renamed over the original, so a crash
        during compaction leaves the old log intact.
        """
        live = {key: self.get(key) for key in self.index}
        temporary = self.path.with_suffix(".compact")

        with temporary.open("wb") as handle:
            new_index: dict[str, int] = {}
            for key, value in live.items():
                record = json.dumps({"key": key, "value": value}) + "\n"
                encoded = record.encode("utf-8")
                new_index[key] = handle.tell()
                handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temporary, self.path)
        removed = len(self.index)  # count before, for the message
        self.index = new_index
        return removed


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="A tiny append-only key-value store")
    parser.add_argument("--store", type=Path, default=Path("store.log"), help="Log file")
    subparsers = parser.add_subparsers(dest="command", required=True)

    setter = subparsers.add_parser("set", help="Set a key")
    setter.add_argument("key")
    setter.add_argument("value")

    getter = subparsers.add_parser("get", help="Get a key")
    getter.add_argument("key")

    deleter = subparsers.add_parser("delete", help="Delete a key")
    deleter.add_argument("key")

    subparsers.add_parser("keys", help="List all keys")
    subparsers.add_parser("compact", help="Reclaim space from dead records")

    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        store = KVStore(args.store)

        if args.command == "set":
            store.set(args.key, args.value)
            print(f"Set {args.key}")
        elif args.command == "get":
            value = store.get(args.key)
            if value is None:
                print(f"[!] {args.key} not found", file=sys.stderr)
                return 1
            print(value)
        elif args.command == "delete":
            if store.delete(args.key):
                print(f"Deleted {args.key}")
            else:
                print(f"[!] {args.key} not found", file=sys.stderr)
                return 1
        elif args.command == "keys":
            for key in store.keys():
                print(key)
        elif args.command == "compact":
            kept = store.compact()
            print(f"Compacted. {kept} live key(s) retained.")
    except KVError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

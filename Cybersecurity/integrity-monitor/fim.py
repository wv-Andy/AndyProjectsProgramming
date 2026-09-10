"""File integrity monitor.

Records a baseline of a directory tree, then detects on later runs what was
added, removed or changed. This is the idea behind host-based intrusion
detection: an attacker who plants a backdoor or edits a config file changes the
filesystem, and a hash of every file will notice.

The baseline is a JSON file. It stores a hash and metadata per file, so a change
in content, size or permissions is caught even when the modification time was
reset to hide the edit.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import sys
import time
from collections.abc import Iterator, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path

BASELINE_VERSION = 1
CHUNK_SIZE = 1 << 16  # 64 KiB, so a large file never loads into memory at once

DEFAULT_IGNORES = (
    "*.pyc", "__pycache__", ".git", ".venv", "venv", "node_modules",
    ".DS_Store", "Thumbs.db", "*.tmp", "*.swp",
)


@dataclass
class FileEntry:
    hash: str
    size: int
    mode: str
    modified: float


@dataclass
class Baseline:
    version: int
    root: str
    algorithm: str
    created: float
    files: dict[str, FileEntry] = field(default_factory=dict)

    def to_json(self) -> dict:
        return {
            "version": self.version,
            "root": self.root,
            "algorithm": self.algorithm,
            "created": self.created,
            "files": {path: asdict(entry) for path, entry in self.files.items()},
        }

    @classmethod
    def from_json(cls, data: dict) -> Baseline:
        return cls(
            version=data["version"],
            root=data["root"],
            algorithm=data.get("algorithm", "sha256"),
            created=data["created"],
            files={path: FileEntry(**entry) for path, entry in data["files"].items()},
        )


@dataclass
class Changes:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    modified: list[tuple[str, list[str]]] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not (self.added or self.removed or self.modified)

    @property
    def total(self) -> int:
        return len(self.added) + len(self.removed) + len(self.modified)


class MonitorError(RuntimeError):
    """Raised when a baseline cannot be built, read or written."""


def should_ignore(relative_path: str, patterns: Sequence[str]) -> bool:
    """Match a path or any of its components against the ignore globs."""
    parts = Path(relative_path).parts
    for pattern in patterns:
        if fnmatch.fnmatch(relative_path, pattern):
            return True
        if any(fnmatch.fnmatch(part, pattern) for part in parts):
            return True
    return False


def hash_file(path: Path, algorithm: str) -> str:
    """Hash a file in chunks, so file size does not dictate memory use."""
    digest = hashlib.new(algorithm)
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(CHUNK_SIZE):
                digest.update(chunk)
    except OSError as exc:
        raise MonitorError(f"Could not read {path}: {exc}") from exc
    return digest.hexdigest()


def walk_files(root: Path, patterns: Sequence[str]) -> Iterator[Path]:
    """Yield every file under root that is not ignored."""
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        # Prune ignored directories in place so os.walk does not descend them.
        dirnames[:] = [
            name
            for name in dirnames
            if not should_ignore(str((current / name).relative_to(root)), patterns)
        ]
        for filename in filenames:
            file_path = current / filename
            relative = str(file_path.relative_to(root))
            if should_ignore(relative, patterns):
                continue
            yield file_path


def build_baseline(root: Path, *, algorithm: str, patterns: Sequence[str]) -> Baseline:
    """Hash every file under root and record it."""
    if not root.is_dir():
        raise MonitorError(f"{root} is not a directory")

    baseline = Baseline(
        version=BASELINE_VERSION,
        root=str(root.resolve()),
        algorithm=algorithm,
        created=time.time(),
    )

    for file_path in walk_files(root, patterns):
        relative = str(file_path.relative_to(root)).replace(os.sep, "/")
        try:
            stat = file_path.stat()
        except OSError:
            continue
        baseline.files[relative] = FileEntry(
            hash=hash_file(file_path, algorithm),
            size=stat.st_size,
            mode=oct(stat.st_mode & 0o777),
            modified=stat.st_mtime,
        )

    return baseline


def compare(baseline: Baseline, current: Baseline) -> Changes:
    """Diff two baselines into added, removed and modified files."""
    changes = Changes()

    old_paths = set(baseline.files)
    new_paths = set(current.files)

    changes.added = sorted(new_paths - old_paths)
    changes.removed = sorted(old_paths - new_paths)

    for path in sorted(old_paths & new_paths):
        old = baseline.files[path]
        new = current.files[path]
        reasons: list[str] = []
        if old.hash != new.hash:
            reasons.append("content")
        if old.size != new.size:
            reasons.append(f"size {old.size} -> {new.size}")
        if old.mode != new.mode:
            reasons.append(f"mode {old.mode} -> {new.mode}")
        if reasons:
            changes.modified.append((path, reasons))

    return changes


def save_baseline(baseline: Baseline, path: Path) -> None:
    try:
        path.write_text(json.dumps(baseline.to_json(), indent=2), encoding="utf-8")
    except OSError as exc:
        raise MonitorError(f"Could not write {path}: {exc}") from exc


def load_baseline(path: Path) -> Baseline:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise MonitorError(f"Could not read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise MonitorError(f"{path} is not a valid baseline: {exc}") from exc
    try:
        return Baseline.from_json(data)
    except (KeyError, TypeError) as exc:
        raise MonitorError(f"{path} is missing expected fields: {exc}") from exc


def print_changes(changes: Changes) -> None:
    if changes.clean:
        print("No changes. The tree matches the baseline.")
        return

    if changes.added:
        print(f"\nAdded ({len(changes.added)}):")
        for path in changes.added:
            print(f"  + {path}")

    if changes.removed:
        print(f"\nRemoved ({len(changes.removed)}):")
        for path in changes.removed:
            print(f"  - {path}")

    if changes.modified:
        print(f"\nModified ({len(changes.modified)}):")
        for path, reasons in changes.modified:
            print(f"  ~ {path}  ({', '.join(reasons)})")

    print(f"\n{changes.total} change(s) detected.")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Baseline a directory tree and detect later changes",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="Create a baseline")
    init.add_argument("directory", type=Path, help="Directory to baseline")
    init.add_argument("--baseline", type=Path, default=Path("baseline.json"), help="Baseline file")
    init.add_argument("--algorithm", default="sha256", help="Hash algorithm (default sha256)")
    init.add_argument("--ignore", action="append", default=[], help="Extra glob to ignore")

    check = subparsers.add_parser("check", help="Compare against a baseline")
    check.add_argument("directory", type=Path, help="Directory to check")
    check.add_argument("--baseline", type=Path, default=Path("baseline.json"), help="Baseline file")
    check.add_argument("--ignore", action="append", default=[], help="Extra glob to ignore")
    check.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    check.add_argument(
        "--update", action="store_true", help="Rewrite the baseline after reporting"
    )

    return parser.parse_args(argv)


def ignore_patterns(args: argparse.Namespace) -> list[str]:
    """Combine the defaults, the user's globs, and the baseline file itself.

    The baseline lives inside the tree by default, so without this it would
    report itself as an added file and then as modified after every update.
    """
    patterns = list(DEFAULT_IGNORES) + args.ignore
    try:
        relative = args.baseline.resolve().relative_to(args.directory.resolve())
        patterns.append(str(relative).replace(os.sep, "/"))
    except (ValueError, OSError):
        pass  # The baseline is outside the tree, so nothing to ignore.
    return patterns


def command_init(args: argparse.Namespace) -> int:
    patterns = ignore_patterns(args)
    baseline = build_baseline(args.directory, algorithm=args.algorithm, patterns=patterns)
    save_baseline(baseline, args.baseline)
    print(f"Baselined {len(baseline.files)} file(s) from {args.directory} into {args.baseline}")
    return 0


def command_check(args: argparse.Namespace) -> int:
    baseline = load_baseline(args.baseline)
    patterns = ignore_patterns(args)
    current = build_baseline(args.directory, algorithm=baseline.algorithm, patterns=patterns)
    changes = compare(baseline, current)

    if args.json:
        print(
            json.dumps(
                {
                    "added": changes.added,
                    "removed": changes.removed,
                    "modified": [
                        {"path": path, "reasons": reasons} for path, reasons in changes.modified
                    ],
                    "total": changes.total,
                },
                indent=2,
            )
        )
    else:
        print_changes(changes)

    if args.update:
        save_baseline(current, args.baseline)
        if not args.json:
            print(f"Baseline updated: {args.baseline}")

    return 0 if changes.clean else 1


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "init":
            return command_init(args)
        return command_check(args)
    except MonitorError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

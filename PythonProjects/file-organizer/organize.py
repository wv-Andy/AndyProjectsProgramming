"""Organise a directory by moving files into folders by type or by date.

A small tool with a serious rule: it never overwrites, and it can always show
what it would do before doing it. Destructive file operations without a dry run
are how people lose data.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# Extension to category, so a folder ends up with "Images", "Documents", etc.
CATEGORIES = {
    "Images": {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp", ".heic", ".tiff"},
    "Documents": {".pdf", ".doc", ".docx", ".txt", ".md", ".rtf", ".odt", ".tex"},
    "Spreadsheets": {".xls", ".xlsx", ".csv", ".ods"},
    "Presentations": {".ppt", ".pptx", ".odp"},
    "Audio": {".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a"},
    "Video": {".mp4", ".avi", ".mkv", ".mov", ".wmv", ".webm"},
    "Archives": {".zip", ".tar", ".gz", ".bz2", ".7z", ".rar", ".xz"},
    "Code": {".py", ".js", ".ts", ".java", ".c", ".cpp", ".go", ".rs", ".sh", ".html", ".css"},
    "Data": {".json", ".xml", ".yaml", ".yml", ".sql", ".db"},
}

# Reverse the map once, for O(1) lookups.
EXTENSION_TO_CATEGORY = {
    extension: category
    for category, extensions in CATEGORIES.items()
    for extension in extensions
}
OTHER_CATEGORY = "Other"


@dataclass
class Move:
    source: Path
    destination: Path


class OrganizeError(RuntimeError):
    """Raised when the directory cannot be organised."""


def category_for(path: Path) -> str:
    return EXTENSION_TO_CATEGORY.get(path.suffix.lower(), OTHER_CATEGORY)


def date_folder(path: Path) -> str:
    """A ``YYYY/YYYY-MM`` folder from the file's modification time."""
    modified = datetime.fromtimestamp(path.stat().st_mtime)
    return f"{modified:%Y}/{modified:%Y-%m}"


def unique_destination(destination: Path, taken: set[Path]) -> Path:
    """Find a name that collides with nothing, on disk or already planned.

    Two files named report.pdf must not become one. The second becomes
    report (1).pdf, and so on.
    """
    if not destination.exists() and destination not in taken:
        return destination

    stem = destination.stem
    suffix = destination.suffix
    parent = destination.parent
    counter = 1
    while True:
        candidate = parent / f"{stem} ({counter}){suffix}"
        if not candidate.exists() and candidate not in taken:
            return candidate
        counter += 1


def plan_moves(directory: Path, *, by: str) -> list[Move]:
    """Work out every move without touching the filesystem."""
    if not directory.is_dir():
        raise OrganizeError(f"{directory} is not a directory")

    moves: list[Move] = []
    taken: set[Path] = set()

    for entry in sorted(directory.iterdir()):
        if entry.is_dir() or entry.name.startswith("."):
            continue

        if by == "type":
            folder = directory / category_for(entry)
        else:
            folder = directory / date_folder(entry)

        destination = unique_destination(folder / entry.name, taken)
        taken.add(destination)
        moves.append(Move(source=entry, destination=destination))

    return moves


def apply_moves(moves: Sequence[Move]) -> int:
    """Carry out the planned moves, creating folders as needed."""
    for move in moves:
        move.destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(move.source), str(move.destination))
    return len(moves)


def summarise(moves: Sequence[Move], directory: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for move in moves:
        folder = move.destination.parent.relative_to(directory).parts[0]
        counts[folder] = counts.get(folder, 0) + 1
    return counts


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Organise a directory into folders by type or by date",
    )
    parser.add_argument("directory", type=Path, help="Directory to organise")
    parser.add_argument(
        "--by", choices=("type", "date"), default="type", help="Group by file type or by date"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would happen without moving anything",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        moves = plan_moves(args.directory, by=args.by)
    except OrganizeError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    if not moves:
        print("Nothing to organise. No files found at the top level.")
        return 0

    if args.dry_run:
        print(f"Dry run: {len(moves)} file(s) would move.\n")
        for move in moves:
            relative = move.destination.relative_to(args.directory)
            print(f"  {move.source.name}  ->  {relative}")
        print("\nRun again without --dry-run to apply.")
        return 0

    count = apply_moves(moves)
    print(f"Moved {count} file(s):")
    for folder, number in sorted(summarise(moves, args.directory).items()):
        print(f"  {folder}: {number}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

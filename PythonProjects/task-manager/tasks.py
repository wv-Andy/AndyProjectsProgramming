"""A command-line task manager with JSON storage.

An exercise in persistence and CRUD through argparse subcommands. Tasks live in a
JSON file, each with an id, a description, a done flag and timestamps.

The storage is written atomically: changes go to a temporary file that is then
renamed over the original, so an interrupted write never leaves a half-written,
corrupt task list.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_STORE = Path.home() / ".tasks.json"


class TaskError(RuntimeError):
    """Raised for user-facing task errors."""


@dataclass
class Task:
    id: int
    description: str
    done: bool = False
    created: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed: str | None = None


def load_tasks(path: Path) -> list[Task]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TaskError(f"Could not read task store {path}: {exc}") from exc
    return [Task(**entry) for entry in data]


def save_tasks(path: Path, tasks: Sequence[Task]) -> None:
    """Write atomically: temp file, flush, fsync, then rename over the target."""
    payload = json.dumps([asdict(task) for task in tasks], indent=2)
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)

    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=directory, delete=False, suffix=".tmp"
    )
    try:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        os.replace(handle.name, path)  # atomic on the same filesystem
    except OSError as exc:
        os.unlink(handle.name)
        raise TaskError(f"Could not write task store {path}: {exc}") from exc


def next_id(tasks: Sequence[Task]) -> int:
    return max((task.id for task in tasks), default=0) + 1


def add_task(tasks: list[Task], description: str) -> Task:
    if not description.strip():
        raise TaskError("A task needs a description")
    task = Task(id=next_id(tasks), description=description.strip())
    tasks.append(task)
    return task


def find_task(tasks: Sequence[Task], task_id: int) -> Task:
    for task in tasks:
        if task.id == task_id:
            return task
    raise TaskError(f"No task with id {task_id}")


def complete_task(tasks: Sequence[Task], task_id: int) -> Task:
    task = find_task(tasks, task_id)
    task.done = True
    task.completed = datetime.now(timezone.utc).isoformat()
    return task


def remove_task(tasks: list[Task], task_id: int) -> Task:
    task = find_task(tasks, task_id)
    tasks.remove(task)
    return task


def filter_tasks(tasks: Sequence[Task], *, show: str) -> list[Task]:
    if show == "done":
        return [task for task in tasks if task.done]
    if show == "pending":
        return [task for task in tasks if not task.done]
    return list(tasks)


def format_task(task: Task) -> str:
    mark = "[x]" if task.done else "[ ]"
    return f"  {task.id:>3} {mark} {task.description}"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="A command-line task manager")
    parser.add_argument("--store", type=Path, default=DEFAULT_STORE, help="Task store file")
    subparsers = parser.add_subparsers(dest="command", required=True)

    add = subparsers.add_parser("add", help="Add a task")
    add.add_argument("description", nargs="+", help="What the task is")

    listing = subparsers.add_parser("list", help="List tasks")
    listing.add_argument(
        "--show", choices=("all", "pending", "done"), default="all", help="Which tasks to show"
    )

    done = subparsers.add_parser("done", help="Mark a task complete")
    done.add_argument("id", type=int, help="Task id")

    remove = subparsers.add_parser("remove", help="Delete a task")
    remove.add_argument("id", type=int, help="Task id")

    subparsers.add_parser("clear", help="Delete completed tasks")

    return parser.parse_args(argv)


def command_add(args: argparse.Namespace, tasks: list[Task]) -> int:
    task = add_task(tasks, " ".join(args.description))
    save_tasks(args.store, tasks)
    print(f"Added task {task.id}: {task.description}")
    return 0


def command_list(args: argparse.Namespace, tasks: list[Task]) -> int:
    selected = filter_tasks(tasks, show=args.show)
    if not selected:
        print("No tasks." if args.show == "all" else f"No {args.show} tasks.")
        return 0
    pending = sum(1 for task in tasks if not task.done)
    print(f"Tasks ({pending} pending, {len(tasks)} total):")
    for task in selected:
        print(format_task(task))
    return 0


def command_done(args: argparse.Namespace, tasks: list[Task]) -> int:
    task = complete_task(tasks, args.id)
    save_tasks(args.store, tasks)
    print(f"Completed task {task.id}: {task.description}")
    return 0


def command_remove(args: argparse.Namespace, tasks: list[Task]) -> int:
    task = remove_task(tasks, args.id)
    save_tasks(args.store, tasks)
    print(f"Removed task {task.id}: {task.description}")
    return 0


def command_clear(args: argparse.Namespace, tasks: list[Task]) -> int:
    remaining = [task for task in tasks if not task.done]
    removed = len(tasks) - len(remaining)
    save_tasks(args.store, remaining)
    print(f"Cleared {removed} completed task(s).")
    return 0


COMMANDS = {
    "add": command_add,
    "list": command_list,
    "done": command_done,
    "remove": command_remove,
    "clear": command_clear,
}


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        tasks = load_tasks(args.store)
        return COMMANDS[args.command](args, tasks)
    except TaskError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

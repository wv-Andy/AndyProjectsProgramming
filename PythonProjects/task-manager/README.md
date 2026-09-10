# Task Manager

A command-line task manager with JSON storage. No dependencies.

An exercise in persistence and CRUD through argparse subcommands. Tasks are kept
in a JSON file, and writes are atomic, so an interrupted save never corrupts the
list.

## Usage

```bash
python tasks.py add "write the README"
python tasks.py list
python tasks.py list --show pending
python tasks.py done 1
python tasks.py remove 2
python tasks.py clear            # delete all completed tasks
```

By default tasks live in `~/.tasks.json`; pass `--store path.json` to use another
file.

## Subcommands

| Command | Does |
|---|---|
| `add <text>` | Add a task |
| `list [--show all\|pending\|done]` | List tasks |
| `done <id>` | Mark a task complete |
| `remove <id>` | Delete a task |
| `clear` | Delete every completed task |

## Atomic writes

The save is the interesting part. Instead of opening the task file and writing
into it, which leaves it half-written if the process dies mid-save, the new
content goes to a temporary file that is flushed and fsynced, then renamed over
the original. `os.replace` is atomic on the same filesystem, so at every instant
the task file is either the complete old version or the complete new one, never a
broken mix.

Task ids come from max-plus-one, not the list length, so removing a task never
causes a later task to reuse a freed id.

## What I learned

- argparse subcommands, the pattern behind `git add` / `git commit`
- Atomic file writes with a temp file, fsync and rename
- Why id assignment from the length is a bug and max-plus-one is not
- `dataclasses` with `asdict` for clean JSON serialisation

## License

MIT, see [LICENSE](../../LICENSE).

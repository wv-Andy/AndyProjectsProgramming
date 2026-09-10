# File Organizer

Sorts a directory into folders by file type or by date. No dependencies.

The feature that matters most is the one you cannot see: it never overwrites a
file, and `--dry-run` shows every move before any of them happen. Destructive
file operations without a preview are how people lose data.

## Usage

```bash
# Preview first, always
python organize.py ~/Downloads --dry-run

# Group by type: Images, Documents, Archives, ...
python organize.py ~/Downloads

# Group by date, into YYYY/YYYY-MM folders
python organize.py ~/Photos --by date
```

### Options

| Flag | Description |
|---|---|
| `--by type` | Group by file category (default) |
| `--by date` | Group by modification date |
| `--dry-run` | Show planned moves without doing anything |

## How it works

The plan and the action are two separate steps. `plan_moves` walks the directory
and returns a list of moves without touching anything; `apply_moves` carries them
out. That separation is what makes the dry run trustworthy: it runs exactly the
same planning code, then stops.

Name collisions are resolved, not ignored. Two files that would both land on
`report.pdf` become `report.pdf` and `report (1).pdf`. The planner tracks names
it has already assigned, so even collisions within a single run are handled.

## What I learned

- `pathlib` for path handling that works the same on Windows and Linux
- Why a dry run has to share the real code path to be worth anything
- Separating "decide what to do" from "do it", which makes both testable
- That safe file tools resolve collisions instead of overwriting

## License

MIT, see [LICENSE](../../LICENSE).

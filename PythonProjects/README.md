# Python Projects

General-purpose Python work: automation, problem solving, and the core language
features worth practising outside a security context.

## Scope

- Automation and scripting
- Data structures and algorithms
- File, text and format handling
- Command-line tool design

## Projects

| Project | Description |
|---|---|
| [file-organizer](file-organizer/) | Sorts a directory by type or date, with a safe dry run |
| [markdown-converter](markdown-converter/) | Markdown to HTML as a line-oriented state machine |
| [task-manager](task-manager/) | CLI task manager with atomic JSON storage |
| [web-scraper](web-scraper/) | Concurrent, polite crawler that obeys robots.txt |
| [kv-database](kv-database/) | Append-only key-value store, the design behind Bitcask |

More planned work is listed in the [roadmap](../Docs/ROADMAP.md).

## Conventions

One folder per project, each with a README and tests in the repository-wide
[`tests/`](../tests/) folder. Standard library first. A project that needs
dependencies carries its own `requirements.txt`.

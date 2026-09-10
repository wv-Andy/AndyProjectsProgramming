# Key-Value Database

A tiny append-only key-value store, the same core design as Bitcask and the
storage layer under LevelDB. No dependencies.

It exists to answer one question: what is a database, underneath the query
language? The answer here is a file, an append, and an in-memory index.

## Usage

```bash
python kvstore.py set name andy
python kvstore.py get name
python kvstore.py delete name
python kvstore.py keys
python kvstore.py compact
```

Pass `--store path.log` to choose the file; it defaults to `store.log`.

## How it works

Four ideas, and that is the whole database.

**Every write is an append.** Setting a key writes a new record to the end of the
log. Nothing is ever overwritten in place. Updating a key appends a newer record;
deleting one appends a tombstone. The old records stay where they are.

**An in-memory index makes reads fast.** A dictionary maps each key to the byte
offset of its latest record. A read is one `seek` and one `readline`, no matter
how big the log has grown.

**Startup replays the log.** The index is rebuilt by reading the log start to
finish, last-write-wins per key. This is also the recovery mechanism.

**Compaction reclaims space.** Superseded and deleted records still take up room.
`compact` rewrites the log with only the live records. On one test, 50 writes to
a single key shrank back to one record.

## Why append-only is safe

Overwriting data in place means a crash mid-write can corrupt a record that was
already good. Appending cannot: the worst a crash can do is leave a half-written
record at the very end, and the index rebuild simply stops at the first line it
cannot parse. Every earlier record is untouched. A test writes a deliberately
torn final record and confirms the rest of the store still loads.

Writes are flushed and fsynced, and compaction writes to a temp file that is
renamed over the original, so an interrupted compaction leaves the old log
intact.

## What I learned

- That a database is a file plus an index, before it is anything else
- The log-structured design, and why append-only survives crashes
- How an in-memory index turns a growing file into O(1) reads
- Tombstones, last-write-wins, and compaction to reclaim space
- Why fsync and atomic rename are what "durable" actually means

## License

MIT, see [LICENSE](../../LICENSE).

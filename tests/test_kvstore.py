"""Tests for the append-only key-value store."""

from __future__ import annotations

import pytest


@pytest.fixture
def store_path(tmp_path):
    return tmp_path / "store.log"


def test_set_and_get(kvstore, store_path):
    store = kvstore.KVStore(store_path)
    store.set("name", "andy")
    assert store.get("name") == "andy"


def test_get_missing_key_is_none(kvstore, store_path):
    store = kvstore.KVStore(store_path)
    assert store.get("absent") is None


def test_update_overwrites_the_value(kvstore, store_path):
    store = kvstore.KVStore(store_path)
    store.set("k", "first")
    store.set("k", "second")
    assert store.get("k") == "second"


def test_delete_removes_the_key(kvstore, store_path):
    store = kvstore.KVStore(store_path)
    store.set("k", "v")
    assert store.delete("k") is True
    assert store.get("k") is None
    assert "k" not in store


def test_delete_missing_key_returns_false(kvstore, store_path):
    store = kvstore.KVStore(store_path)
    assert store.delete("absent") is False


def test_empty_key_is_rejected(kvstore, store_path):
    store = kvstore.KVStore(store_path)
    with pytest.raises(kvstore.KVError):
        store.set("", "v")


def test_keys_are_sorted(kvstore, store_path):
    store = kvstore.KVStore(store_path)
    store.set("banana", "1")
    store.set("apple", "2")
    store.set("cherry", "3")
    assert store.keys() == ["apple", "banana", "cherry"]


def test_len_counts_live_keys(kvstore, store_path):
    store = kvstore.KVStore(store_path)
    store.set("a", "1")
    store.set("b", "2")
    store.delete("a")
    assert len(store) == 1


# --- Durability and recovery ----------------------------------------------


def test_index_survives_a_reopen(kvstore, store_path):
    """A fresh KVStore rebuilds its index by replaying the log."""
    store = kvstore.KVStore(store_path)
    store.set("persisted", "value")
    store.set("updated", "old")
    store.set("updated", "new")
    store.delete("persisted")

    reopened = kvstore.KVStore(store_path)
    assert reopened.get("updated") == "new"
    assert reopened.get("persisted") is None


def test_replay_applies_last_write_wins(kvstore, store_path):
    store = kvstore.KVStore(store_path)
    for value in ("a", "b", "c"):
        store.set("k", value)
    reopened = kvstore.KVStore(store_path)
    assert reopened.get("k") == "c"


def test_a_torn_final_record_is_ignored(kvstore, store_path):
    """A crash mid-write leaves a partial last line; recovery must not choke."""
    store = kvstore.KVStore(store_path)
    store.set("good", "value")
    # Simulate an interrupted append: a half-written record with no newline.
    with store_path.open("ab") as handle:
        handle.write(b'{"key": "bad", "val')

    reopened = kvstore.KVStore(store_path)
    assert reopened.get("good") == "value"
    assert reopened.get("bad") is None


# --- Compaction -----------------------------------------------------------


def test_compaction_preserves_live_data(kvstore, store_path):
    store = kvstore.KVStore(store_path)
    store.set("keep", "final")
    store.set("keep", "superseded-then-final")
    store.set("keep", "final")
    store.set("gone", "x")
    store.delete("gone")

    store.compact()
    assert store.get("keep") == "final"
    assert store.get("gone") is None


def test_compaction_shrinks_the_log(kvstore, store_path):
    store = kvstore.KVStore(store_path)
    for index in range(50):
        store.set("k", f"value-{index}")  # 50 writes, one live value
    size_before = store_path.stat().st_size
    store.compact()
    size_after = store_path.stat().st_size
    assert size_after < size_before
    assert store.get("k") == "value-49"


def test_store_survives_compaction_and_reopen(kvstore, store_path):
    store = kvstore.KVStore(store_path)
    store.set("a", "1")
    store.set("b", "2")
    store.compact()
    reopened = kvstore.KVStore(store_path)
    assert reopened.get("a") == "1"
    assert reopened.get("b") == "2"


# --- CLI ------------------------------------------------------------------


def test_cli_set_get_delete(kvstore, store_path):
    assert kvstore.main(["--store", str(store_path), "set", "name", "andy"]) == 0
    assert kvstore.main(["--store", str(store_path), "get", "name"]) == 0
    assert kvstore.main(["--store", str(store_path), "delete", "name"]) == 0
    assert kvstore.main(["--store", str(store_path), "get", "name"]) == 1  # now missing

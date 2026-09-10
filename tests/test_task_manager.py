"""Tests for the task manager. The store is a real temporary JSON file."""

from __future__ import annotations

import json

import pytest


@pytest.fixture
def store(tmp_path):
    return tmp_path / "tasks.json"


def test_add_and_load(task_manager, store):
    tasks = []
    task_manager.add_task(tasks, "write tests")
    task_manager.save_tasks(store, tasks)
    loaded = task_manager.load_tasks(store)
    assert len(loaded) == 1
    assert loaded[0].description == "write tests"
    assert loaded[0].done is False


def test_ids_increment(task_manager):
    tasks = []
    first = task_manager.add_task(tasks, "one")
    second = task_manager.add_task(tasks, "two")
    assert first.id == 1
    assert second.id == 2


def test_ids_do_not_reuse_after_removal(task_manager):
    tasks = []
    task_manager.add_task(tasks, "one")
    task_manager.add_task(tasks, "two")
    task_manager.remove_task(tasks, 1)
    third = task_manager.add_task(tasks, "three")
    assert third.id == 3  # not 2, the max-plus-one rule holds


def test_empty_description_is_rejected(task_manager):
    with pytest.raises(task_manager.TaskError):
        task_manager.add_task([], "   ")


def test_complete_sets_done_and_timestamp(task_manager):
    tasks = []
    task_manager.add_task(tasks, "finish")
    completed = task_manager.complete_task(tasks, 1)
    assert completed.done is True
    assert completed.completed is not None


def test_find_missing_task_raises(task_manager):
    with pytest.raises(task_manager.TaskError):
        task_manager.find_task([], 99)


def test_remove_task(task_manager):
    tasks = []
    task_manager.add_task(tasks, "delete me")
    task_manager.remove_task(tasks, 1)
    assert tasks == []


def test_filter_pending_and_done(task_manager):
    tasks = []
    task_manager.add_task(tasks, "a")
    task_manager.add_task(tasks, "b")
    task_manager.complete_task(tasks, 1)
    assert len(task_manager.filter_tasks(tasks, show="done")) == 1
    assert len(task_manager.filter_tasks(tasks, show="pending")) == 1
    assert len(task_manager.filter_tasks(tasks, show="all")) == 2


def test_load_missing_file_is_empty(task_manager, tmp_path):
    assert task_manager.load_tasks(tmp_path / "absent.json") == []


def test_save_is_atomic_and_valid_json(task_manager, store):
    tasks = []
    task_manager.add_task(tasks, "one")
    task_manager.save_tasks(store, tasks)
    # The file is complete, valid JSON, with no leftover temp file.
    data = json.loads(store.read_text(encoding="utf-8"))
    assert data[0]["description"] == "one"
    assert not list(store.parent.glob("*.tmp"))


def test_load_rejects_corrupt_json(task_manager, store):
    store.write_text("not json", encoding="utf-8")
    with pytest.raises(task_manager.TaskError):
        task_manager.load_tasks(store)


def test_round_trip_preserves_everything(task_manager, store):
    tasks = []
    task_manager.add_task(tasks, "keep me")
    task_manager.complete_task(tasks, 1)
    task_manager.save_tasks(store, tasks)
    loaded = task_manager.load_tasks(store)
    assert loaded[0].done is True
    assert loaded[0].completed is not None


# --- CLI ------------------------------------------------------------------


def test_cli_add_then_list(task_manager, store, capsys):
    assert task_manager.main(["--store", str(store), "add", "buy", "milk"]) == 0
    assert task_manager.main(["--store", str(store), "list"]) == 0
    output = capsys.readouterr().out
    assert "buy milk" in output


def test_cli_done_and_clear(task_manager, store):
    task_manager.main(["--store", str(store), "add", "task one"])
    task_manager.main(["--store", str(store), "done", "1"])
    task_manager.main(["--store", str(store), "clear"])
    assert task_manager.load_tasks(store) == []


def test_cli_done_missing_id_fails(task_manager, store):
    task_manager.main(["--store", str(store), "add", "task"])
    assert task_manager.main(["--store", str(store), "done", "99"]) == 1

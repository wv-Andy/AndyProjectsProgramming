"""Tests for the file integrity monitor.

Every test builds a real directory tree in a temporary path, so the walking,
hashing and diffing are exercised end to end without any mocking.
"""

from __future__ import annotations

import json

import pytest


def make_tree(root):
    (root / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (root / "config.ini").write_text("[main]\ndebug=false\n", encoding="utf-8")
    sub = root / "lib"
    sub.mkdir()
    (sub / "helper.py").write_text("def help():\n    pass\n", encoding="utf-8")
    return root


# --- Baseline building ----------------------------------------------------


def test_build_baseline_records_every_file(fim, tmp_path):
    make_tree(tmp_path)
    baseline = fim.build_baseline(tmp_path, algorithm="sha256", patterns=[])
    assert set(baseline.files) == {"app.py", "config.ini", "lib/helper.py"}


def test_build_baseline_rejects_a_file(fim, tmp_path):
    target = tmp_path / "file.txt"
    target.write_text("x", encoding="utf-8")
    with pytest.raises(fim.MonitorError):
        fim.build_baseline(target, algorithm="sha256", patterns=[])


def test_hashes_are_stable(fim, tmp_path):
    make_tree(tmp_path)
    first = fim.build_baseline(tmp_path, algorithm="sha256", patterns=[])
    second = fim.build_baseline(tmp_path, algorithm="sha256", patterns=[])
    assert first.files["app.py"].hash == second.files["app.py"].hash


def test_hash_matches_hashlib(fim, tmp_path):
    import hashlib

    (tmp_path / "x.txt").write_bytes(b"content")
    baseline = fim.build_baseline(tmp_path, algorithm="sha256", patterns=[])
    assert baseline.files["x.txt"].hash == hashlib.sha256(b"content").hexdigest()


# --- Ignore patterns ------------------------------------------------------


def test_default_ignores_skip_pycache(fim, tmp_path):
    make_tree(tmp_path)
    cache = tmp_path / "__pycache__"
    cache.mkdir()
    (cache / "app.cpython-312.pyc").write_bytes(b"\x00")
    baseline = fim.build_baseline(tmp_path, algorithm="sha256", patterns=fim.DEFAULT_IGNORES)
    assert not any("pycache" in path for path in baseline.files)


def test_custom_ignore_glob(fim, tmp_path):
    make_tree(tmp_path)
    (tmp_path / "secret.log").write_text("x", encoding="utf-8")
    baseline = fim.build_baseline(tmp_path, algorithm="sha256", patterns=["*.log"])
    assert "secret.log" not in baseline.files


def test_should_ignore_matches_a_component(fim):
    assert fim.should_ignore("lib/.git/config", [".git"]) is True
    assert fim.should_ignore("lib/helper.py", [".git"]) is False


# --- Change detection -----------------------------------------------------


def test_detects_an_added_file(fim, tmp_path):
    make_tree(tmp_path)
    baseline = fim.build_baseline(tmp_path, algorithm="sha256", patterns=[])
    (tmp_path / "new.py").write_text("x = 1\n", encoding="utf-8")
    current = fim.build_baseline(tmp_path, algorithm="sha256", patterns=[])
    changes = fim.compare(baseline, current)
    assert changes.added == ["new.py"]
    assert not changes.removed and not changes.modified


def test_detects_a_removed_file(fim, tmp_path):
    make_tree(tmp_path)
    baseline = fim.build_baseline(tmp_path, algorithm="sha256", patterns=[])
    (tmp_path / "config.ini").unlink()
    current = fim.build_baseline(tmp_path, algorithm="sha256", patterns=[])
    changes = fim.compare(baseline, current)
    assert changes.removed == ["config.ini"]


def test_detects_modified_content(fim, tmp_path):
    make_tree(tmp_path)
    baseline = fim.build_baseline(tmp_path, algorithm="sha256", patterns=[])
    (tmp_path / "app.py").write_text("print('goodbye')\n", encoding="utf-8")
    current = fim.build_baseline(tmp_path, algorithm="sha256", patterns=[])
    changes = fim.compare(baseline, current)
    assert len(changes.modified) == 1
    path, reasons = changes.modified[0]
    assert path == "app.py"
    assert "content" in reasons


def test_content_change_is_caught_even_at_the_same_size(fim, tmp_path):
    """A hash catches an edit that keeps the byte count identical."""
    (tmp_path / "f.txt").write_text("aaaa", encoding="utf-8")
    baseline = fim.build_baseline(tmp_path, algorithm="sha256", patterns=[])
    (tmp_path / "f.txt").write_text("bbbb", encoding="utf-8")
    current = fim.build_baseline(tmp_path, algorithm="sha256", patterns=[])
    changes = fim.compare(baseline, current)
    assert changes.modified
    assert "content" in changes.modified[0][1]


def test_an_unchanged_tree_is_clean(fim, tmp_path):
    make_tree(tmp_path)
    baseline = fim.build_baseline(tmp_path, algorithm="sha256", patterns=[])
    current = fim.build_baseline(tmp_path, algorithm="sha256", patterns=[])
    assert fim.compare(baseline, current).clean is True


# --- Persistence ----------------------------------------------------------


def test_baseline_round_trips_through_json(fim, tmp_path):
    make_tree(tmp_path)
    baseline = fim.build_baseline(tmp_path, algorithm="sha256", patterns=[])
    path = tmp_path / "baseline.json"
    fim.save_baseline(baseline, path)
    loaded = fim.load_baseline(path)
    assert loaded.files == baseline.files
    assert loaded.algorithm == baseline.algorithm


def test_load_rejects_invalid_json(fim, tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("not json", encoding="utf-8")
    with pytest.raises(fim.MonitorError):
        fim.load_baseline(path)


def test_load_rejects_missing_fields(fim, tmp_path):
    path = tmp_path / "incomplete.json"
    path.write_text(json.dumps({"version": 1}), encoding="utf-8")
    with pytest.raises(fim.MonitorError):
        fim.load_baseline(path)


# --- CLI ------------------------------------------------------------------


def test_cli_init_then_clean_check(fim, tmp_path):
    make_tree(tmp_path)
    baseline = tmp_path / "baseline.json"
    assert fim.main(["init", str(tmp_path), "--baseline", str(baseline)]) == 0
    assert baseline.is_file()
    # A clean check exits 0. The baseline file itself must not be flagged.
    assert fim.main(["check", str(tmp_path), "--baseline", str(baseline)]) == 0


def test_cli_check_detects_a_change_with_exit_code(fim, tmp_path):
    make_tree(tmp_path)
    baseline = tmp_path / "baseline.json"
    fim.main(["init", str(tmp_path), "--baseline", str(baseline)])
    (tmp_path / "app.py").write_text("tampered\n", encoding="utf-8")
    # A dirty check exits 1.
    assert fim.main(["check", str(tmp_path), "--baseline", str(baseline)]) == 1


def test_cli_update_refreshes_the_baseline(fim, tmp_path):
    make_tree(tmp_path)
    baseline = tmp_path / "baseline.json"
    fim.main(["init", str(tmp_path), "--baseline", str(baseline)])
    (tmp_path / "app.py").write_text("changed\n", encoding="utf-8")
    fim.main(["check", str(tmp_path), "--baseline", str(baseline), "--update"])
    # After --update, the next check is clean.
    assert fim.main(["check", str(tmp_path), "--baseline", str(baseline)]) == 0


def test_cli_missing_baseline_is_an_error(fim, tmp_path):
    assert fim.main(["check", str(tmp_path), "--baseline", str(tmp_path / "nope.json")]) == 2

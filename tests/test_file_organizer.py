"""Tests for the file organizer. Every test uses a real temporary directory."""

from __future__ import annotations

import pytest


def touch(directory, name, content="x"):
    path = directory / name
    path.write_text(content, encoding="utf-8")
    return path


def test_category_for_known_and_unknown(file_organizer):
    from pathlib import Path

    assert file_organizer.category_for(Path("photo.jpg")) == "Images"
    assert file_organizer.category_for(Path("report.pdf")) == "Documents"
    assert file_organizer.category_for(Path("archive.zip")) == "Archives"
    assert file_organizer.category_for(Path("mystery.xyz")) == "Other"


def test_category_is_case_insensitive(file_organizer):
    from pathlib import Path

    assert file_organizer.category_for(Path("PHOTO.JPG")) == "Images"


def test_plan_moves_groups_by_type(file_organizer, tmp_path):
    touch(tmp_path, "a.jpg")
    touch(tmp_path, "b.pdf")
    touch(tmp_path, "c.png")
    moves = file_organizer.plan_moves(tmp_path, by="type")
    destinations = {move.source.name: move.destination.parent.name for move in moves}
    assert destinations == {"a.jpg": "Images", "b.pdf": "Documents", "c.png": "Images"}


def test_plan_moves_does_not_touch_the_filesystem(file_organizer, tmp_path):
    original = touch(tmp_path, "a.jpg")
    file_organizer.plan_moves(tmp_path, by="type")
    assert original.exists()  # planning alone moves nothing


def test_plan_skips_dotfiles_and_directories(file_organizer, tmp_path):
    touch(tmp_path, "a.jpg")
    touch(tmp_path, ".hidden")
    (tmp_path / "subdir").mkdir()
    moves = file_organizer.plan_moves(tmp_path, by="type")
    assert [move.source.name for move in moves] == ["a.jpg"]


def test_name_collisions_are_resolved(file_organizer, tmp_path):
    """Two files that would land on the same name must not overwrite."""
    touch(tmp_path, "a.jpg")
    # Pre-create the destination so the planned move must find a new name.
    images = tmp_path / "Images"
    images.mkdir()
    touch(images, "a.jpg", content="existing")
    moves = file_organizer.plan_moves(tmp_path, by="type")
    assert moves[0].destination.name == "a (1).jpg"


def test_apply_moves_relocates_files(file_organizer, tmp_path):
    touch(tmp_path, "a.jpg")
    touch(tmp_path, "b.pdf")
    moves = file_organizer.plan_moves(tmp_path, by="type")
    file_organizer.apply_moves(moves)
    assert (tmp_path / "Images" / "a.jpg").exists()
    assert (tmp_path / "Documents" / "b.pdf").exists()
    assert not (tmp_path / "a.jpg").exists()


def test_apply_moves_does_not_lose_content(file_organizer, tmp_path):
    touch(tmp_path, "a.jpg", content="important data")
    moves = file_organizer.plan_moves(tmp_path, by="type")
    file_organizer.apply_moves(moves)
    assert (tmp_path / "Images" / "a.jpg").read_text(encoding="utf-8") == "important data"


def test_plan_by_date_uses_year_month(file_organizer, tmp_path):
    touch(tmp_path, "a.jpg")
    moves = file_organizer.plan_moves(tmp_path, by="date")
    # The destination is nested YYYY/YYYY-MM.
    parts = moves[0].destination.parent.parts
    assert parts[-2].isdigit() and len(parts[-2]) == 4  # year
    assert "-" in parts[-1]  # year-month


def test_plan_rejects_a_non_directory(file_organizer, tmp_path):
    target = touch(tmp_path, "a.jpg")
    with pytest.raises(file_organizer.OrganizeError):
        file_organizer.plan_moves(target, by="type")


def test_cli_dry_run_moves_nothing(file_organizer, tmp_path):
    original = touch(tmp_path, "a.jpg")
    assert file_organizer.main([str(tmp_path), "--dry-run"]) == 0
    assert original.exists()


def test_cli_applies_moves(file_organizer, tmp_path):
    touch(tmp_path, "a.jpg")
    assert file_organizer.main([str(tmp_path)]) == 0
    assert (tmp_path / "Images" / "a.jpg").exists()

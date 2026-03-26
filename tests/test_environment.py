"""Tests for environment inspection."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

from pyguard.environment import (
    _find_pth_files,
    _find_startup_file,
)


class TestFindPthFiles:
    def test_finds_pth_files(self, tmp_path):
        (tmp_path / "somepkg.pth").write_text("/some/path\n")
        (tmp_path / "other.pth").write_text("/other/path\n")
        (tmp_path / "notpth.txt").write_text("ignored")

        result = _find_pth_files([tmp_path])
        names = {p.name for p in result}
        assert "somepkg.pth" in names
        assert "other.pth" in names
        assert "notpth.txt" not in names

    def test_empty_directory(self, tmp_path):
        result = _find_pth_files([tmp_path])
        assert result == []

    def test_multiple_site_packages(self, tmp_path):
        dir1 = tmp_path / "site1"
        dir2 = tmp_path / "site2"
        dir1.mkdir()
        dir2.mkdir()
        (dir1 / "a.pth").write_text("")
        (dir2 / "b.pth").write_text("")

        result = _find_pth_files([dir1, dir2])
        assert len(result) == 2


class TestFindStartupFile:
    def test_finds_sitecustomize(self, tmp_path):
        sc = tmp_path / "sitecustomize.py"
        sc.write_text("# test")
        result = _find_startup_file("sitecustomize.py", [tmp_path])
        assert result == sc

    def test_returns_none_when_absent(self, tmp_path):
        result = _find_startup_file("sitecustomize.py", [tmp_path])
        assert result is None

    def test_finds_in_first_matching_dir(self, tmp_path):
        dir1 = tmp_path / "sp1"
        dir2 = tmp_path / "sp2"
        dir1.mkdir()
        dir2.mkdir()
        sc2 = dir2 / "sitecustomize.py"
        sc2.write_text("# in sp2")
        result = _find_startup_file("sitecustomize.py", [dir1, dir2])
        assert result == sc2

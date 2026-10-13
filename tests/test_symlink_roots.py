from pathlib import Path

import pytest

from devguard.cli import main
from devguard.scanner import iter_source_files, scan_file


def _symlink_or_skip(link: Path, target: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not supported in this environment")


def test_explicit_symlink_file_root_is_rejected(tmp_path: Path):
    target = tmp_path / "outside.py"
    target.write_text("eval(user_input)\n", encoding="utf-8")
    link = tmp_path / "linked.py"
    _symlink_or_skip(link, target)

    with pytest.raises(OSError, match="refusing to scan symbolic link"):
        list(iter_source_files(link))


def test_scan_file_rejects_symlink(tmp_path: Path):
    target = tmp_path / "outside.py"
    target.write_text("eval(user_input)\n", encoding="utf-8")
    link = tmp_path / "linked.py"
    _symlink_or_skip(link, target)

    with pytest.raises(OSError, match="refusing to scan symbolic link"):
        scan_file(link)


def test_explicit_symlink_directory_root_is_rejected(tmp_path: Path):
    target = tmp_path / "outside"
    target.mkdir()
    (target / "sample.py").write_text("print('safe')\n", encoding="utf-8")
    link = tmp_path / "linked-dir"
    _symlink_or_skip(link, target, directory=True)

    with pytest.raises(OSError, match="refusing to scan symbolic link"):
        list(iter_source_files(link))


def test_cli_returns_error_for_explicit_symlink_root(tmp_path: Path, monkeypatch, capsys):
    target = tmp_path / "outside.py"
    target.write_text("print('safe')\n", encoding="utf-8")
    link = tmp_path / "linked.py"
    _symlink_or_skip(link, target)
    monkeypatch.setattr("sys.argv", ["devguard", "scan", str(link)])

    assert main() == 2
    assert "refusing to scan symbolic link" in capsys.readouterr().err

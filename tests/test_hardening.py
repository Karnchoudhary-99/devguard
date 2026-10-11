from pathlib import Path

import pytest

from devguard import scanner
from devguard.cli import main
from devguard.scanner import iter_source_files, scan_file


def _write_sample(path: Path, content: str = "print('safe')\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_single_star_does_not_match_across_directory_boundaries(tmp_path: Path):
    _write_sample(tmp_path / "src" / "top.py")
    _write_sample(tmp_path / "src" / "nested" / "deep.py")
    paths = list(iter_source_files(tmp_path, exclude=["src/*.py"]))
    assert paths == [tmp_path / "src" / "nested" / "deep.py"]


def test_recursive_glob_matches_root_and_nested_files(tmp_path: Path):
    _write_sample(tmp_path / "root.py")
    _write_sample(tmp_path / "nested" / "deep.py")
    assert list(iter_source_files(tmp_path, exclude=["**/*.py"])) == []


def test_recursive_directory_exclusion_prunes_the_tree(tmp_path: Path):
    _write_sample(tmp_path / "generated" / "nested" / "output.py")
    _write_sample(tmp_path / "src" / "source.py")
    paths = list(iter_source_files(tmp_path, exclude=["generated/**"]))
    assert paths == [tmp_path / "src" / "source.py"]


def test_file_iteration_is_deterministic_within_a_directory(tmp_path: Path):
    _write_sample(tmp_path / "z.py")
    _write_sample(tmp_path / "a.py")
    _write_sample(tmp_path / "m.py")
    names = [path.name for path in iter_source_files(tmp_path)]
    assert names == ["a.py", "m.py", "z.py"]


def test_explicit_file_scan_still_accepts_non_source_suffix(tmp_path: Path):
    path = tmp_path / "sample.txt"
    _write_sample(path)
    assert list(iter_source_files(path)) == [path]


def test_scan_skips_symlinked_files_and_directories(tmp_path: Path):
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    _write_sample(root / "safe.py")
    _write_sample(outside / "linked.py", "eval(user_input)\n")
    try:
        (root / "linked.py").symlink_to(outside / "linked.py")
        (root / "linked-dir").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not supported in this environment")
    assert list(iter_source_files(root)) == [root / "safe.py"]


def test_scan_file_streams_lines_and_keeps_line_numbers(tmp_path: Path):
    path = tmp_path / "sample.py"
    _write_sample(path, "print('safe')\n# another line\nvalue = eval(user_input)\n")
    findings = scan_file(path)
    assert [(item.rule_id, item.line) for item in findings] == [("SEC-001", 3)]


def test_unreadable_source_file_is_not_reported_as_clean(tmp_path: Path, monkeypatch):
    path = tmp_path / "unreadable.py"
    _write_sample(path)
    original_open = Path.open

    def denied(self, *args, **kwargs):
        if self == path:
            raise PermissionError("permission denied")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", denied)
    with pytest.raises(OSError, match="cannot read source file"):
        scan_file(path)


def test_unreadable_ignore_file_is_not_silently_ignored(tmp_path: Path, monkeypatch):
    _write_sample(tmp_path / "sample.py")
    ignore_file = tmp_path / ".devguardignore"
    original_read_text = Path.read_text

    def denied(self, *args, **kwargs):
        if self == ignore_file:
            raise PermissionError("permission denied")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", denied)
    with pytest.raises(OSError, match="cannot read ignore file"):
        list(iter_source_files(tmp_path))


def test_walk_errors_abort_scan(tmp_path: Path, monkeypatch):
    def broken_walk(top, topdown=True, onerror=None, followlinks=False):
        if onerror:
            onerror(PermissionError("permission denied"))
        yield str(tmp_path), [], []

    monkeypatch.setattr(scanner.os, "walk", broken_walk)
    with pytest.raises(PermissionError, match="permission denied"):
        list(iter_source_files(tmp_path))


def test_cli_returns_error_for_scan_io_failure(tmp_path: Path, monkeypatch, capsys):
    def fail_scan(*args, **kwargs):
        raise PermissionError("permission denied")

    monkeypatch.setattr("devguard.cli.scan", fail_scan)
    monkeypatch.setattr("sys.argv", ["devguard", "scan", str(tmp_path)])
    assert main() == 2
    assert "permission denied" in capsys.readouterr().err

from pathlib import Path

from devguard.scanner import iter_source_files


def _write_sample(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("print('safe')\n", encoding="utf-8")


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

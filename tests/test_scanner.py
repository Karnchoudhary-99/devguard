from pathlib import Path
from devguard.scanner import scan, scan_file

def test_detects_eval(tmp_path: Path):
    p = tmp_path / "sample.py"
    p.write_text("result = eval(user_input)\n", encoding="utf-8")
    findings = scan_file(p)
    assert any(f.rule_id == "SEC-001" and f.line == 1 for f in findings)

def test_detects_hardcoded_secret(tmp_path: Path):
    p = tmp_path / "config.py"
    p.write_text('api_key = "supersecretvalue"\n', encoding="utf-8")
    findings = scan(p)
    assert any(f.rule_id == "SECRET-GENERIC" for f in findings)

def test_ignores_git_directory(tmp_path: Path):
    git = tmp_path / ".git"
    git.mkdir()
    (git / "bad.py").write_text("eval(x)\n", encoding="utf-8")
    assert scan(tmp_path) == []

def test_clean_file_has_no_findings(tmp_path: Path):
    p = tmp_path / "clean.py"
    p.write_text("print('hello')\n", encoding="utf-8")
    assert scan_file(p) == []

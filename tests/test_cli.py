import json
import sys
from pathlib import Path

from devguard.cli import main
from devguard.scanner import scan


def test_json_report_has_machine_readable_findings(tmp_path: Path, monkeypatch, capsys):
    source = tmp_path / "sample.py"
    source.write_text("value = eval(user_input)\n", encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["devguard", "scan", str(tmp_path), "--format", "json"],
    )

    assert main() == 1
    report = json.loads(capsys.readouterr().out)
    assert report["count"] == 1
    assert report["findings"][0]["rule_id"] == "SEC-001"
    assert report["findings"][0]["line"] == 1


def test_auto_config_excludes_generated_paths(tmp_path: Path, monkeypatch, capsys):
    generated = tmp_path / "generated"
    generated.mkdir()
    (generated / "unsafe.py").write_text("eval(user_input)\n", encoding="utf-8")
    (tmp_path / ".devguard.json").write_text(
        json.dumps({"exclude": ["generated/**"]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["devguard", "scan", str(tmp_path), "--format", "json"],
    )

    assert main() == 0
    assert json.loads(capsys.readouterr().out)["count"] == 0


def test_invalid_config_fails_with_actionable_error(tmp_path: Path, monkeypatch, capsys):
    config = tmp_path / "bad-config.json"
    config.write_text('{"exclude": "generated"}', encoding="utf-8")
    source = tmp_path / "sample.py"
    source.write_text("print('safe')\n", encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["devguard", "scan", str(source), "--config", str(config)],
    )

    assert main() == 2
    assert "exclude" in capsys.readouterr().err


def test_devguardignore_and_cli_exclusions(tmp_path: Path):
    ignored = tmp_path / "ignored.py"
    ignored.write_text("value = eval(user_input)\n", encoding="utf-8")
    (tmp_path / ".devguardignore").write_text(
        "# generated code\nignored.py\n",
        encoding="utf-8",
    )
    assert scan(tmp_path) == []

    (tmp_path / ".devguardignore").unlink()
    assert scan(tmp_path, exclude=["ignored.py"]) == []


def test_secret_finding_snippet_is_redacted(tmp_path: Path):
    source = "password = " + repr("redaction-test-value") + "\n"
    path = tmp_path / "sample.py"
    path.write_text(source, encoding="utf-8")

    finding = next(item for item in scan(path) if item.rule_id == "SECRET-GENERIC")

    assert "redaction-test-value" not in finding.snippet
    assert "[REDACTED]" in finding.snippet

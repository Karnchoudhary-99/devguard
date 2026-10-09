from pathlib import Path

import pytest

from devguard.scanner import scan_file


@pytest.mark.parametrize(
    ("source", "expected_rule"),
    [
        ('api_key = "supersecretvalue"\n', "SECRET-GENERIC"),
        ("AWS_ACCESS_KEY_ID = AKIA1234567890ABCDEF\n", "SECRET-AWS"),
        ('token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"\n', "SECRET-GITHUB"),
        ("-----BEGIN RSA PRIVATE KEY-----\n", "SECRET-PRIVATE-KEY"),
    ],
)
def test_detects_secret_patterns(tmp_path: Path, source: str, expected_rule: str):
    path = tmp_path / "sample.py"
    path.write_text(source, encoding="utf-8")

    findings = scan_file(path)

    assert any(f.rule_id == expected_rule and f.line == 1 for f in findings)


def test_aws_rule_does_not_match_short_identifier(tmp_path: Path):
    path = tmp_path / "sample.py"
    path.write_text("AWS_ACCESS_KEY_ID = AKIA1234\n", encoding="utf-8")

    assert not any(f.rule_id == "SECRET-AWS" for f in scan_file(path))


def test_github_rule_does_not_match_short_token(tmp_path: Path):
    path = tmp_path / "sample.py"
    path.write_text('token = "ghp_short"\n', encoding="utf-8")

    assert not any(f.rule_id == "SECRET-GITHUB" for f in scan_file(path))

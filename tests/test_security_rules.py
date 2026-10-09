from pathlib import Path

import pytest

from devguard.scanner import scan_file


@pytest.mark.parametrize(
    ("source", "expected_rule"),
    [
        ("subprocess.run(command, shell=True)\n", "SEC-003"),
        ("pickle.loads(untrusted_data)\n", "SEC-004"),
        ("yaml.load(untrusted_data)\n", "SEC-005"),
        ("requests.get(url, verify=False)\n", "SEC-006"),
    ],
)
def test_detects_unsafe_patterns(tmp_path: Path, source: str, expected_rule: str):
    path = tmp_path / "sample.py"
    path.write_text(source, encoding="utf-8")

    findings = scan_file(path)

    assert any(f.rule_id == expected_rule and f.line == 1 for f in findings)


@pytest.mark.parametrize(
    "source",
    [
        "subprocess.run(command, shell=False)\n",
        "pickle.dumps(value)\n",
        "yaml.safe_load(untrusted_data)\n",
        "requests.get(url, verify=True)\n",
    ],
)
def test_safe_alternatives_do_not_trigger_new_rules(tmp_path: Path, source: str):
    path = tmp_path / "sample.py"
    path.write_text(source, encoding="utf-8")

    findings = scan_file(path)

    assert not any(f.rule_id in {"SEC-003", "SEC-004", "SEC-005", "SEC-006"} for f in findings)

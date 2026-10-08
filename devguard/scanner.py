from pathlib import Path
from typing import Iterable, List
from .models import Finding
from .rules import RULES

DEFAULT_EXCLUDED = {".git", ".venv", "venv", "__pycache__", "node_modules"}

def iter_source_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in DEFAULT_EXCLUDED for part in path.parts):
            continue
        if path.suffix.lower() in {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb", ".php", ".json", ".yml", ".yaml", ".env", ".ini", ".cfg"}:
            yield path

def scan_file(path: Path) -> List[Finding]:
    findings = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return findings
    for number, line in enumerate(lines, 1):
        for rule in RULES:
            if rule.pattern.search(line):
                findings.append(Finding(rule.rule_id, rule.severity, rule.message, path, number, line.strip()[:240]))
    return findings

def scan(root: Path) -> List[Finding]:
    findings = []
    for path in iter_source_files(root):
        findings.extend(scan_file(path))
    return findings

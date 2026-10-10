import fnmatch
from pathlib import Path
from typing import Iterable, List

from .models import Finding
from .rules import RULES

DEFAULT_EXCLUDED = {".git", ".venv", "venv", "__pycache__", "node_modules"}
SOURCE_SUFFIXES = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb", ".php",
    ".json", ".yml", ".yaml", ".env", ".ini", ".cfg",
}


def _read_ignore_patterns(root: Path) -> List[str]:
    ignore_file = root / ".devguardignore"
    try:
        lines = ignore_file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return [
        line.strip().rstrip("/")
        for line in lines
        if line.strip() and not line.lstrip().startswith("#") and line.strip().rstrip("/")
    ]


def _is_excluded(relative: Path, patterns: Iterable[str]) -> bool:
    value = relative.as_posix()
    parts = relative.parts
    for raw_pattern in patterns:
        pattern = raw_pattern.strip().replace("\\", "/").rstrip("/")
        if not pattern:
            continue
        if fnmatch.fnmatchcase(value, pattern):
            return True
        if "/" not in pattern and any(fnmatch.fnmatchcase(part, pattern) for part in parts):
            return True
        for index in range(1, len(parts)):
            if fnmatch.fnmatchcase("/".join(parts[:index]), pattern):
                return True
    return False


def iter_source_files(root: Path, exclude: Iterable[str] = ()) -> Iterable[Path]:
    patterns = _read_ignore_patterns(root) + list(exclude)
    if root.is_file():
        if not _is_excluded(Path(root.name), patterns):
            yield root
        return
    if not root.is_dir():
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in DEFAULT_EXCLUDED for part in relative.parts[:-1]):
            continue
        if _is_excluded(relative, patterns):
            continue
        if path.suffix.lower() in SOURCE_SUFFIXES:
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
                safe_line = line
                if rule.rule_id.startswith("SECRET-"):
                    safe_line = rule.pattern.sub("[REDACTED]", safe_line)
                findings.append(
                    Finding(
                        rule.rule_id,
                        rule.severity,
                        rule.message,
                        path,
                        number,
                        safe_line.strip()[:240],
                    )
                )
    return findings


def scan(root: Path, exclude: Iterable[str] = ()) -> List[Finding]:
    findings = []
    for path in iter_source_files(root, exclude=exclude):
        findings.extend(scan_file(path))
    return findings

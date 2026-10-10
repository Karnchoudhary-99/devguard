import fnmatch
import os
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

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
        line.strip().replace("\\", "/").rstrip("/")
        for line in lines
        if line.strip() and not line.lstrip().startswith("#")
        and line.strip().replace("\\", "/").rstrip("/")
    ]


def _glob_matches(path_parts: Sequence[str], pattern_parts: Sequence[str]) -> bool:
    """Match path components, treating ** as zero or more whole components."""
    previous = [False] * (len(path_parts) + 1)
    previous[0] = True

    for pattern_part in pattern_parts:
        current = [False] * (len(path_parts) + 1)
        if pattern_part == "**":
            current[0] = previous[0]
            for index in range(1, len(path_parts) + 1):
                current[index] = previous[index] or current[index - 1]
        else:
            for index in range(1, len(path_parts) + 1):
                current[index] = (
                    previous[index - 1]
                    and fnmatch.fnmatchcase(path_parts[index - 1], pattern_part)
                )
        previous = current

    return previous[-1]


def _is_excluded(relative: Path, patterns: Iterable[str]) -> bool:
    parts = relative.parts
    for raw_pattern in patterns:
        pattern = raw_pattern.strip().replace("\\", "/").rstrip("/")
        if not pattern:
            continue

        if "/" not in pattern:
            if any(fnmatch.fnmatchcase(part, pattern) for part in parts):
                return True
            continue

        pattern_parts: Tuple[str, ...] = tuple(part for part in pattern.split("/") if part)
        if _glob_matches(parts, pattern_parts):
            return True

        for index in range(1, len(parts)):
            if _glob_matches(parts[:index], pattern_parts):
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

    for current, directories, filenames in os.walk(str(root), topdown=True, followlinks=False):
        current_path = Path(current)
        relative_current = current_path.relative_to(root)
        directories[:] = sorted(
            name
            for name in directories
            if name not in DEFAULT_EXCLUDED
            and not _is_excluded(relative_current / name, patterns)
        )

        for filename in sorted(filenames):
            path = current_path / filename
            if not path.is_file():
                continue
            relative = path.relative_to(root)
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

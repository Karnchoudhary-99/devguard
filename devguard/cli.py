import argparse
import json
import sys
from pathlib import Path
from typing import List

from .scanner import scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devguard",
        description="Scan source code for common security issues.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan_parser = sub.add_parser("scan", help="Scan a file or directory")
    scan_parser.add_argument("path", nargs="?", default=".", help="Path to scan")
    scan_parser.add_argument("--quiet", action="store_true", help="Only return the exit status")
    scan_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="output_format",
        help="Output format (default: text)",
    )
    scan_parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="Exclude a path or glob pattern; may be supplied more than once",
    )
    scan_parser.add_argument(
        "--config",
        help="JSON configuration file (defaults to .devguard.json in the scan directory)",
    )
    return parser


def _load_config(path: Path) -> List[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError("cannot read configuration file {}: {}".format(path, exc)) from exc
    except json.JSONDecodeError as exc:
        raise ValueError("invalid JSON in configuration file {}: {}".format(path, exc)) from exc

    if not isinstance(data, dict):
        raise ValueError("configuration must be a JSON object")
    unknown = sorted(set(data) - {"exclude"})
    if unknown:
        raise ValueError("unsupported configuration key(s): {}".format(", ".join(unknown)))
    excludes = data.get("exclude", [])
    if not isinstance(excludes, list) or any(
        not isinstance(pattern, str) or not pattern.strip() for pattern in excludes
    ):
        raise ValueError("configuration key 'exclude' must be a list of non-empty strings")
    return excludes


def main() -> int:
    args = build_parser().parse_args()
    if args.command != "scan":
        return 2

    root = Path(args.path)
    if not root.exists():
        print("error: path does not exist: {}".format(root), file=sys.stderr)
        return 2
    if not root.is_file() and not root.is_dir():
        print("error: path is not a regular file or directory: {}".format(root), file=sys.stderr)
        return 2

    config_path = Path(args.config) if args.config else (
        root / ".devguard.json" if root.is_dir() else None
    )
    config_excludes = []
    if config_path is not None and (args.config or config_path.exists()):
        try:
            config_excludes = _load_config(config_path)
        except ValueError as exc:
            print("error: {}".format(exc), file=sys.stderr)
            return 2

    findings = scan(root, exclude=[*config_excludes, *args.exclude])
    if args.quiet:
        return 1 if findings else 0

    if args.output_format == "json":
        report = {
            "root": str(root),
            "count": len(findings),
            "findings": [
                {
                    "path": str(finding.path),
                    "line": finding.line,
                    "severity": finding.severity,
                    "rule_id": finding.rule_id,
                    "message": finding.message,
                    "snippet": finding.snippet,
                }
                for finding in findings
            ],
        }
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for finding in findings:
            print(
                "{}:{}: [{}] {} - {}".format(
                    finding.path,
                    finding.line,
                    finding.severity,
                    finding.rule_id,
                    finding.message,
                )
            )
            if finding.snippet:
                print("  {}".format(finding.snippet))
        print("Scanned {}; findings: {}".format(root, len(findings)))

    return 1 if findings else 0

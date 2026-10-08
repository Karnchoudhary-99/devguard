import argparse
from pathlib import Path
from .scanner import scan

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="devguard", description="Scan source code for common security issues.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan_parser = sub.add_parser("scan", help="Scan a file or directory")
    scan_parser.add_argument("path", nargs="?", default=".", help="Path to scan")
    scan_parser.add_argument("--quiet", action="store_true", help="Only return the exit status")
    return parser

def main() -> int:
    args = build_parser().parse_args()
    if args.command == "scan":
        root = Path(args.path)
        if not root.exists():
            print(f"error: path does not exist: {root}")
            return 2
        findings = scan(root)
        if not args.quiet:
            for f in findings:
                print(f"{f.path}:{f.line}: [{f.severity}] {f.rule_id} - {f.message}")
                if f.snippet:
                    print(f"  {f.snippet}")
            print(f"Scanned {root}; findings: {len(findings)}")
        return 1 if findings else 0
    return 2

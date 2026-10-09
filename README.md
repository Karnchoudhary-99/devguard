# DevGuard

DevGuard is a lightweight developer security and code-quality scanner for local source trees.

## Status

Day 2 of a 7-day build: CLI/scanner foundation is in place, with expanded detection for generic hardcoded secrets, AWS access key IDs, GitHub token formats, private-key headers, and unsafe dynamic execution calls.

## Goals

- Detect common hardcoded secrets and insecure code patterns.
- Produce readable findings with file, line, rule, and severity.
- Support CI-friendly exit codes.
- Keep scanning deterministic, fast, and easy to extend.

## Quick start

```bash
python -m devguard --help
python -m devguard scan .
```

A finding causes exit code `1`; a clean scan exits `0`. Invalid usage/configuration exits non-zero.

## Project roadmap

1. CLI foundation and scanner engine
2. Secret detection engine
3. Security/code-pattern rules
4. Configuration, ignore rules, and reporting
5. GitHub Actions / CI integration
6. Tests, edge cases, performance and security hardening
7. Documentation, final verification and release cleanup

Secret patterns are heuristic indicators, not proof of compromise. Review findings before taking action, and avoid pasting real credentials into issues or logs.

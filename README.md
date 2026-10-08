# DevGuard

DevGuard is a lightweight developer security and code-quality scanner for local source trees.

## Status

Day 1 of a 7-day build: CLI foundation and the first safe, dependency-free scanner rules are implemented.

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

# DevGuard

DevGuard is a lightweight developer security and code-quality scanner for local source trees.

## Status

Day 3 of a 7-day build: the scanner detects common hardcoded credentials, private-key headers, unsafe dynamic execution, risky shell-enabled subprocess calls, pickle deserialization, YAML loading that needs review, and disabled TLS certificate verification. GitHub Actions tests Python 3.9 and 3.12, and its CLI smoke test uses a clean temporary source directory so test fixtures do not make the smoke test fail.

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

## Current checks

- **Secrets:** generic hardcoded secret assignments, AWS access key IDs, GitHub token-like strings, and private-key headers.
- **Dynamic execution:** `eval()` and `exec()`.
- **Risky APIs:** subprocess calls with `shell=True`, `pickle.load(s)`, `yaml.load()` for manual review, and `verify=False` TLS settings.

These are heuristic, line-oriented checks rather than a full language parser. They can miss multiline or obfuscated cases and may flag benign code. In particular, `yaml.load()` is reported for review even when a safe loader argument is supplied. Review findings in context; never paste real credentials into issues or logs.

## Project roadmap

1. CLI foundation and scanner engine
2. Secret detection engine
3. Security/code-pattern rules
4. Configuration, ignore rules, and reporting
5. GitHub Actions / CI integration
6. Tests, edge cases, performance and security hardening
7. Documentation, final verification and release cleanup

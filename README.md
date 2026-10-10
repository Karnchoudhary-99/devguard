# DevGuard

DevGuard is a lightweight developer security and code-quality scanner for local source trees.

## Status

Day 5 of a maximum 7-day build. DevGuard detects common hardcoded credentials and risky API patterns, supports configurable exclusions and JSON reports, redacts matched secret material from finding snippets, and prunes ignored directories during deterministic traversal. GitHub Actions runs the test suite on Python 3.9 and 3.12.

## Install

    python -m pip install -e ".[test]"

## Quick start

    python -m devguard --help
    python -m devguard scan .
    python -m devguard scan src --format json
    python -m devguard scan . --exclude "generated/**" --exclude "vendor/**"

A finding causes exit code 1; a clean scan exits 0. Invalid paths or configuration exit 2. The --quiet option suppresses output and preserves the same exit codes.

## Configuration

When scanning a directory, DevGuard automatically reads a .devguard.json file at that directory's root. The supported key is exclude, a list of glob patterns:

    {
      "exclude": ["generated/**", "vendor/**", "tests/fixtures/**"]
    }

Use --config PATH to select a different configuration file. Invalid JSON, unsupported keys, and invalid exclude values fail with an actionable error instead of silently changing scan scope.

A .devguardignore file can contain one exclusion pattern per line. Blank lines and lines beginning with # are ignored. A pattern without a slash matches any path component. In path patterns, * matches within one path component and ** matches zero or more path components. Command-line exclusions and configuration exclusions are combined with .devguardignore entries. Common generated or dependency directories (.git, .venv, venv, __pycache__, and node_modules) are excluded by default and pruned from traversal.

## Reports and secret handling

Text output is the default. Use --format json for machine-readable output containing the scan root, finding count, and each finding's path, line, severity, rule ID, message, and snippet. Secret-rule snippets replace matched material with [REDACTED] so ordinary reports are less likely to expose credentials. Other code snippets may still contain sensitive context; review report handling before uploading artifacts or posting logs.

## Current checks

- Secrets: generic hardcoded credentials, cloud access key identifiers, source-hosting token-like strings, and private-key headers.
- Dynamic execution APIs.
- Risky subprocess shell mode, deserialization, YAML loading, and disabled TLS verification.

These are heuristic, line-oriented checks rather than a full language parser. They can miss multiline or obfuscated cases and may flag benign code. Review findings in context and never paste real credentials into issues or logs.

## Development plan

1. CLI foundation and scanner engine
2. Secret detection engine
3. Risky API rules and continuous integration
4. Configuration, ignore rules, JSON reporting, and safe snippets
5. Edge cases, performance, and usability hardening
6. Security review and documentation polish
7. Final verification and release cleanup

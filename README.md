# DevGuard

DevGuard is a lightweight, line-oriented security and code-quality scanner for local source trees.

## Status and scope

**Scope-frozen baseline: v0.1.0.** The current implementation detects selected hardcoded credential patterns and risky API usage, supports configurable exclusions and JSON reports, redacts matched secret material from finding snippets, and prunes ignored directories during deterministic traversal. Scanning streams files line by line and reports incomplete scans as errors instead of silently claiming a clean result.

The CI suite covers Python 3.9, 3.12, and 3.14, including compilation, automated tests, package builds, and smoke tests of the installed command-line tool. Changes beyond this baseline should be handled as a separately scoped follow-up rather than silently expanding this completed build.

## Requirements and installation

Python 3.9 or newer is required.

Install from a local checkout:

    python -m pip install .

For development and tests:

    python -m pip install -e ".[test]"
    python -m pytest -q

## Quick start

    devguard --help
    devguard scan .
    devguard scan src --format json
    devguard scan . --exclude "generated/**" --exclude "vendor/**"

A finding causes exit code 1; a clean scan exits 0. Invalid paths, configuration errors, symbolic-link roots, or unreadable source/ignore paths exit 2. The `--quiet` option suppresses output and preserves the same exit codes.

## Configuration

When scanning a directory, DevGuard automatically reads a `.devguard.json` file at that directory's root. The supported key is `exclude`, a list of glob patterns:

    {
      "exclude": ["generated/**", "vendor/**", "tests/fixtures/**"]
    }

Use `--config PATH` to select a different configuration file. Invalid JSON, unsupported keys, and invalid exclude values fail with an actionable error instead of silently changing scan scope.

A `.devguardignore` file can contain one exclusion pattern per line. Blank lines and lines beginning with `#` are ignored. A pattern without a slash matches any path component. In path patterns, `*` matches within one path component and `**` matches zero or more path components. Command-line exclusions and configuration exclusions are combined with `.devguardignore` entries. Common generated or dependency directories (`.git`, `.venv`, `venv`, `__pycache__`, and `node_modules`) are excluded by default and pruned from traversal.

## Reports and secret handling

Text output is the default. Use `--format json` for machine-readable output containing the scan root, finding count, and each finding's path, line, severity, rule ID, message, and snippet. Secret-rule snippets replace matched material with `[REDACTED]` so ordinary reports are less likely to expose credentials. Other code snippets may still contain sensitive context; review report handling before uploading artifacts or posting logs.

Directory scans skip symlinked files and directories rather than following paths outside the selected tree. Explicitly supplied symbolic-link scan roots are rejected as errors. If a source file, ignore file, or directory cannot be read, scanning stops with an error (exit code 2) instead of returning a potentially misleading clean result. File content is processed one line at a time to reduce peak memory use.

## Current checks

- Secrets: generic hardcoded credentials, cloud access key identifiers, source-hosting token-like strings, and private-key headers.
- Dynamic execution APIs.
- Risky subprocess shell mode, deserialization, YAML loading, and disabled TLS verification.

These are heuristic, line-oriented checks rather than a full language parser. They can miss multiline, obfuscated, or unsupported patterns and may flag benign code. A clean scan is not a guarantee that code is secure. Review findings in context and never paste real credentials into issues or logs.

## License

DevGuard is distributed under the MIT License; see [LICENSE](LICENSE).

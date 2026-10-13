# 🛡️ DevGuard

<div align="center">

### Lightweight Security & Code Quality Scanner

**Scan smart. Catch risks. Ship with confidence.**

A lightweight, line-oriented scanner that helps developers identify hardcoded credentials, risky API usage, and common security anti-patterns in local source trees.

[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
![Version](https://img.shields.io/badge/version-0.1.0-red?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Focused-B22222?style=for-the-badge&logo=shield&logoColor=white)

[Getting Started](#-getting-started) · [Features](#-features) · [Configuration](#-configuration) · [Security Model](#-security-model) · [Limitations](#-limitations)

</div>

---

## ⚡ Overview

DevGuard is a lightweight, developer-friendly security and code-quality scanner designed to inspect local source trees without requiring a heavyweight analysis platform.

It focuses on practical, heuristic-based checks that help identify potentially dangerous code patterns early in the development workflow.

```bash
devguard scan .
```

One command. Actionable findings. Machine-readable reports when you need them.

### Why DevGuard?

- 🔐 **Secret detection** — Identify selected hardcoded credential patterns and token-like strings.
- ⚠️ **Risky API detection** — Flag selected dynamic execution, subprocess, deserialization, YAML, and TLS-related patterns.
- 🧹 **Configurable exclusions** — Keep generated files, dependencies, and irrelevant paths out of scope.
- 🛡️ **Secret redaction** — Replace matched secret material in secret-rule finding snippets with `[REDACTED]`.
- 📄 **JSON reporting** — Integrate findings into scripts and downstream tooling.
- ⚙️ **Deterministic traversal** — Prune ignored directories and avoid following symbolic links.
- 📉 **Memory-conscious scanning** — Process source files one line at a time.
- 🚨 **Explicit failure handling** — Report incomplete scans as errors instead of silently claiming success.

---

## ✨ Features

| Capability | Description |
|---|---|
| Credential scanning | Detect selected hardcoded credentials, cloud access key identifiers, source-hosting token-like strings, and private-key headers. |
| Risky API checks | Flag selected dynamic execution, risky subprocess shell mode, deserialization, YAML loading, and disabled TLS verification patterns. |
| Flexible exclusions | Combine CLI exclusions, `.devguard.json` configuration, and `.devguardignore` patterns. |
| Directory pruning | Exclude common generated and dependency directories before descending into them. |
| JSON output | Produce machine-readable findings with paths, line numbers, severity, rule IDs, messages, and snippets. |
| Secret redaction | Redact matched material for secret-rule finding snippets. |
| Safe traversal | Skip symlinked files and directories; reject symbolic-link scan roots. |
| Error-aware scanning | Return an error when required files or directories cannot be read. |
| Streaming file processing | Read source files line by line to reduce peak memory use. |

---

## 🚀 Getting Started

### Requirements

- Python 3.9 or newer
- pip
- A local source tree to scan

### 1. Install DevGuard

From the project checkout:

```bash
python -m pip install .
```

### 2. Verify the installation

```bash
devguard --help
```

### 3. Run your first scan

Scan the current directory:

```bash
devguard scan .
```

Scan a specific source directory:

```bash
devguard scan src
```

Generate a JSON report:

```bash
devguard scan src --format json
```

Exclude generated and vendor directories:

```bash
devguard scan . \
  --exclude "generated/**" \
  --exclude "vendor/**"
```

### 4. Development installation

Install the project in editable mode with test dependencies:

```bash
python -m pip install -e ".[test]"
```

Run the test suite:

```bash
python -m pytest -q
```

---

## 🧪 How It Works

```text
        ┌───────────────────────┐
        │   Source Tree / Path  │
        └───────────┬───────────┘
                    │
                    ▼
        ┌───────────────────────┐
        │ Resolve Scan Settings │
        │ CLI + Config + Ignore │
        └───────────┬───────────┘
                    │
                    ▼
        ┌───────────────────────┐
        │ Prune Excluded Paths  │
        │ Skip Symbolic Links   │
        └───────────┬───────────┘
                    │
                    ▼
        ┌───────────────────────┐
        │ Stream Files by Line  │
        │ Apply Security Rules  │
        └───────────┬───────────┘
                    │
                    ▼
        ┌───────────────────────┐
        │ Build Findings        │
        │ Redact Secret Snippets│
        └───────────┬───────────┘
                    │
                    ▼
        ┌───────────────────────┐
        │ Text / JSON Report    │
        │ Exit Status           │
        └───────────────────────┘
```

DevGuard combines configured exclusions, deterministic directory traversal, line-oriented rule checks, and structured reporting into a simple local scanning workflow.

If scanning cannot be completed reliably, DevGuard reports an error rather than presenting an incomplete result as a clean scan.

---

## 🔍 Current Security Checks

### 🔐 Secrets and credentials

- Generic hardcoded credential patterns
- Cloud access key identifiers
- Source-hosting token-like strings
- Private-key headers

### ⚠️ Risky API usage

- Dynamic code execution APIs
- Risky subprocess shell mode
- Deserialization APIs
- YAML loading patterns
- Disabled TLS certificate verification

> **Important:** These are heuristic, line-oriented checks, not a full language parser. Detection depends on the supported patterns and source layout.

---

## ⚙️ Configuration

DevGuard automatically reads `.devguard.json` from the root of a directory being scanned.

### Example: `.devguard.json`

```json
{
  "exclude": [
    "generated/**",
    "vendor/**",
    "tests/fixtures/**"
  ]
}
```

The supported configuration key is `exclude`, which accepts a list of glob patterns.

Use a custom configuration file:

```bash
devguard scan src --config PATH
```

Invalid JSON, unsupported configuration keys, and invalid exclusion values produce actionable errors rather than silently changing the scan scope.

### `.devguardignore`

Create a `.devguardignore` file in the directory being scanned:

```gitignore
# Generated artifacts
generated/**
build/**
dist/**

# Dependencies and fixtures
vendor/**
tests/fixtures/**
```

Blank lines and lines beginning with `#` are ignored.

### Pattern rules

| Pattern | Behavior |
|---|---|
| `*.py` | Matches a filename pattern within one path component. |
| `generated/**` | Matches paths under the generated directory. |
| `**` | Matches zero or more path components when used as a recursive glob. |
| `vendor/` | Does not have a special trailing-slash meaning beyond the scanner's documented glob semantics. |

A pattern without a slash matches any path component. `*` matches within one path component, while `**` can match zero or more path components.

**Exclusion precedence:** CLI exclusions, configuration exclusions, and `.devguardignore` entries are combined. Common generated or dependency directories are excluded by default and pruned from traversal:

- `.git`
- `.venv`
- `venv`
- `__pycache__`
- `node_modules`

---

## 📊 Output and Exit Codes

DevGuard uses exit codes that are suitable for shell scripts and CI workflows.

| Exit code | Meaning |
|---:|---|
| `0` | Scan completed with no findings. |
| `1` | One or more findings were detected. |
| `2` | Scan could not be completed reliably because of invalid paths, configuration errors, symbolic-link roots, or unreadable required paths. |

### Text output

```bash
devguard scan .
```

### JSON output

```bash
devguard scan . --format json
```

JSON reports include:

- Scan root
- Finding count
- Finding path
- Line number
- Severity
- Rule ID
- Message
- Code snippet

### Quiet mode

```bash
devguard scan . --quiet
```

The `--quiet` option suppresses output while preserving the same exit-code behavior.

---

## 🛡️ Security Model

DevGuard incorporates several defensive behaviors intended to make local scans more predictable.

### Secret redaction

Secret-rule finding snippets replace matched secret material with:

```text
[REDACTED]
```

This reduces the chance of exposing credentials in ordinary reports.

**Redaction is not a guarantee that every report is safe to share.** Non-secret findings can still contain sensitive code context. Review reports before uploading CI artifacts, sharing logs, or publishing results.

### Symbolic-link handling

- Symbolic-link files and directories encountered during directory traversal are skipped.
- Explicitly supplied symbolic-link scan roots are rejected.
- Paths outside the selected tree are not followed through encountered symbolic links.

### Incomplete scans

If a source file, ignore file, or directory cannot be read, scanning stops with an error.

This avoids returning a potentially misleading clean result when part of the requested scan was not completed.

### Memory-conscious processing

Source files are processed one line at a time to reduce peak memory consumption.

---

## 🧰 Development and Quality Checks

Install development dependencies:

```bash
python -m pip install -e ".[test]"
```

Run tests:

```bash
python -m pytest -q
```

Compile-check the project:

```bash
python -m compileall -q .
```

The project's CI suite covers:

- Python 3.9
- Python 3.12
- Python 3.14
- Compilation checks
- Automated tests
- Package builds
- Smoke tests of the installed command-line tool

These checks help validate compatibility and packaging across the supported CI matrix.

---

## 🎯 Project Status

<div align="center">

### Scope-Frozen Baseline · `v0.1.0`

**The current implementation is the defined baseline.**

</div>

DevGuard's v0.1.0 scope includes the documented heuristic checks, configuration and exclusions, JSON reports, secret-snippet redaction, deterministic traversal, and incomplete-scan error handling.

Changes beyond this baseline should be managed as a separately scoped follow-up instead of silently expanding the completed build.

---

## ⚖️ Limitations

DevGuard is designed as a lightweight first-pass scanner, not as a complete security verification system.

- It can miss multiline, obfuscated, or unsupported patterns.
- Heuristic checks can flag benign code.
- Detection is limited to the implemented rules.
- Secret redaction applies to matched material in secret-rule finding snippets; it does not guarantee that all sensitive information is removed from reports.
- A clean scan does not prove that a codebase is secure.

Use DevGuard alongside code review, dependency checks, appropriate testing, and other security controls.

Review findings in context. Never paste real credentials into issues or logs.

---

## 📜 License

DevGuard is distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

<div align="center">

**DevGuard — Practical security checks for your local source tree.**

*Lightweight by design. Explicit about its limits.*

</div>

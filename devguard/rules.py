import re
from dataclasses import dataclass
from typing import Pattern


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    message: str
    pattern: Pattern[str]


# Keep patterns line-oriented so the scanner can report precise source locations.
RULES = (
    Rule(
        "SECRET-GENERIC",
        "HIGH",
        "Possible hardcoded secret",
        re.compile(
            r"""(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*['"][^'"]{8,}['"]"""
        ),
    ),
    Rule(
        "SECRET-AWS",
        "CRITICAL",
        "Possible AWS access key ID",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ),
    Rule(
        "SECRET-GITHUB",
        "HIGH",
        "Possible GitHub personal access token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    ),
    Rule(
        "SECRET-PRIVATE-KEY",
        "CRITICAL",
        "Private key material header",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    Rule("SEC-001", "HIGH", "Possible use of eval()", re.compile(r"\beval\s*\(")),
    Rule("SEC-002", "MEDIUM", "Possible use of exec()", re.compile(r"\bexec\s*\(")),
    Rule(
        "SEC-003",
        "HIGH",
        "Subprocess call enables a shell; review command-injection risk",
        re.compile(
            r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\([^\n]*\bshell\s*=\s*True\b"
        ),
    ),
    Rule(
        "SEC-004",
        "HIGH",
        "Unsafe pickle deserialization can execute attacker-controlled code",
        re.compile(r"\bpickle\.(?:load|loads)\s*\("),
    ),
    Rule(
        "SEC-005",
        "MEDIUM",
        "Review yaml.load; prefer safe_load or SafeLoader for untrusted input",
        re.compile(r"\byaml\.load\s*\("),
    ),
    Rule(
        "SEC-006",
        "HIGH",
        "TLS certificate verification is disabled",
        re.compile(r"\bverify\s*=\s*False\b"),
    ),
)

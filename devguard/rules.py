import re
from dataclasses import dataclass
from typing import Pattern

@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    message: str
    pattern: Pattern[str]

RULES = (
    Rule("SECRET-GENERIC", "HIGH", "Possible hardcoded secret", re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"
    )),
    Rule("SEC-001", "HIGH", "Possible use of eval()", re.compile(r"\beval\s*\(")),
    Rule("SEC-002", "MEDIUM", "Possible use of exec()", re.compile(r"\bexec\s*\(")),
)

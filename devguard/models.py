from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    path: Path
    line: int
    snippet: str

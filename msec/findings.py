"""Finding model. Severity is assigned by check code only; nothing downstream may change it."""
import hashlib
import json
from dataclasses import dataclass, field

SEVERITIES = ("critical", "high", "medium", "info")
CATEGORIES = ("persistence", "agent-config", "agent-permissions", "packages", "updates", "ioc")
STATUSES = ("ok", "findings", "not_scanned")


def clean(text, limit: int = 200) -> str:
    """One line, printable, bounded. Scanned strings are attacker-controlled."""
    s = "".join(ch if ch.isprintable() else " " for ch in str(text))
    return " ".join(s.split())[:limit]


@dataclass(frozen=True)
class Finding:
    check: str
    category: str
    severity: str
    title: str
    key: dict
    details: dict = field(default_factory=dict)
    fix: tuple[str, ...] = ()

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity {self.severity!r}")
        if self.category not in CATEGORIES:
            raise ValueError(f"bad category {self.category!r}")
        object.__setattr__(self, "title", clean(self.title))

    @property
    def fingerprint(self) -> str:
        blob = json.dumps({"check": self.check, "key": self.key}, sort_keys=True, ensure_ascii=True)
        return hashlib.sha256(blob.encode()).hexdigest()[:16]

    def to_json(self) -> dict:
        return {"fingerprint": self.fingerprint, "check": self.check, "category": self.category,
                "severity": self.severity, "title": self.title, "key": self.key,
                "details": self.details, "fix": list(self.fix)}


@dataclass(frozen=True)
class CheckResult:
    check: str
    status: str
    findings: tuple[Finding, ...] = ()
    reason: str = ""

    def __post_init__(self):
        if self.status not in STATUSES:
            raise ValueError(f"bad status {self.status!r}")


def result(check: str, findings: list[Finding]) -> CheckResult:
    return CheckResult(check, "findings" if findings else "ok", tuple(findings))


def not_scanned(check: str, reason: str) -> CheckResult:
    return CheckResult(check, "not_scanned", (), clean(reason))

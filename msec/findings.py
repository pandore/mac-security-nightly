"""Finding model. Severity is assigned by check code only; nothing downstream may change it."""
import hashlib
import json
import re
from dataclasses import dataclass, field

SEVERITIES = ("critical", "high", "medium", "info")
CATEGORIES = ("persistence", "agent-config", "agent-permissions", "packages", "updates", "ioc", "coverage")
STATUSES = ("ok", "findings", "not_scanned")

URL = re.compile(r"([A-Za-z][A-Za-z0-9+.-]{0,30}://)(?:[^\s/?#]*@)?([^\s?#]*)([?#]\S*)?")
TOKEN = re.compile(r"\b(sk-ant-|sk-|ghp_|gho_|ghs_|github_pat_|xox[abpr]-|tvly-|AKIA|AIza|glpat-|pplx-)[A-Za-z0-9_-]{6,}")
LONG_RUN = re.compile(r"[A-Za-z0-9_-]{20,}")


def _long_run(m) -> str:
    s = m.group(0)
    return "…redacted…" if re.search(r"[A-Za-z]", s) and re.search(r"[0-9]", s) else s


def mask(s: str) -> str:
    """Drop URL userinfo/query/fragment and token-looking runs. Titles go to the model and state files."""
    s = URL.sub(lambda m: m.group(1) + m.group(2) + ("?…" if m.group(3) else ""), s)
    s = TOKEN.sub(lambda m: m.group(1) + "…", s)
    return LONG_RUN.sub(_long_run, s)


def clean(text, limit: int = 200) -> str:
    """One line, printable, secrets masked, bounded. Scanned strings are attacker-controlled."""
    s = "".join(ch if ch.isprintable() else " " for ch in str(text))
    return mask(" ".join(s.split()))[:limit]


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
        # severity is part of identity: an accepted info item that turns critical (MAL-, fix shipped) is new
        blob = json.dumps({"check": self.check, "key": self.key, "severity": self.severity},
                          sort_keys=True, ensure_ascii=True)
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

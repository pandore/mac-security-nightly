"""summary.json and the outward message. The message uses only counts and the category enum."""
import re

from .findings import CATEGORIES, SEVERITIES, CheckResult, Finding

ALERT_SEVERITIES = ("critical", "high", "medium")
ICONS = {"critical": "🔴", "high": "🟠", "medium": "🟡"}
RUN_ID = re.compile(r"\d{4}-\d{2}-\d{2}")


def build(run_id: str, new: list[Finding], open_critical: list[Finding], results: list[CheckResult]) -> dict:
    counts = {s: sum(1 for f in new if f.severity == s) for s in SEVERITIES}
    cats = {f.category for f in new if f.severity in ALERT_SEVERITIES} | {f.category for f in open_critical}
    return {"run_id": run_id, "counts": counts, "open_critical": len(open_critical),
            "categories": sorted(cats),
            "not_scanned": sorted(r.check for r in results if r.status == "not_scanned")}


def _count(v) -> bool:
    return type(v) is int and 0 <= v <= 9999


def validate(s: dict) -> dict:
    if not (isinstance(s.get("run_id"), str) and RUN_ID.fullmatch(s["run_id"])):
        raise ValueError("summary.run_id")
    counts = s.get("counts")
    if not (isinstance(counts, dict) and set(counts) == set(SEVERITIES) and all(map(_count, counts.values()))):
        raise ValueError("summary.counts")
    if not _count(s.get("open_critical")):
        raise ValueError("summary.open_critical")
    cats = s.get("categories")
    if not (isinstance(cats, list) and all(c in CATEGORIES for c in cats)):
        raise ValueError("summary.categories")
    return s


def message(s: dict) -> str | None:
    """Text for notification adapters, or None when there is nothing to alert on."""
    s = validate(s)
    c = s["counts"]
    if not any(c[k] for k in ALERT_SEVERITIES) and not s["open_critical"]:
        return None
    day = f"{s['run_id'][8:10]}.{s['run_id'][5:7]}"
    marks = " ".join(f"{ICONS[k]}{c[k]}" for k in ALERT_SEVERITIES)
    tail = f" (+{s['open_critical']} відкритих 🔴)" if s["open_critical"] else ""
    return f"🛡 Mac {day}: {marks}{tail} — {', '.join(s['categories'])}. Звіт на маку."

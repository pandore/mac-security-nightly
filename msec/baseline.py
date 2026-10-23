"""seen.json (written nightly) = what was already shown; baseline.json (msec accept only) = what is accepted."""
import json
import os
from datetime import date, timedelta
from pathlib import Path

from .state import ensure_dir, read_json, write_json


def classify(findings, seen: dict, accepted: dict, today: date):
    """-> (new, open_items, accepted_now, resolved_fingerprints)."""
    new, open_items, acc, current = [], [], [], set()
    for f in findings:
        fp = f.fingerprint
        current.add(fp)
        a = accepted.get(fp)
        if a and date.fromisoformat(a["until"]) >= today:
            acc.append(f)
        elif fp not in seen or (a and seen[fp].get("last_seen", "") <= a["until"]):
            new.append(f)                  # never shown, or first night after the acceptance expired
        else:
            open_items.append(f)
    return new, open_items, acc, sorted(set(seen) - current)


CARRY_OVER_DAYS = 3


def _covered(source: str, skipped) -> bool:
    # a ".partial" gap covers only its own base source; a fully skipped check also covers its "<check>.*" sub-sources
    return any(source == s.removesuffix(".partial") or (not s.endswith(".partial") and source.startswith(s + "."))
               for s in skipped)


def update_seen(seen: dict, findings, today: date, sources: dict | None = None, skipped=()) -> dict:
    """Resolved items drop out, so a reappearance counts as new.
    sources: fingerprint -> CheckResult name. skipped: not_scanned check names tonight; items from those
    checks are absent because nothing looked, so they are carried over instead of counted as resolved."""
    sources = sources or {}
    out = {}
    for f in findings:
        prev = seen.get(f.fingerprint, {})
        out[f.fingerprint] = {"first_seen": prev.get("first_seen", today.isoformat()),
                              "last_seen": today.isoformat(), "severity": f.severity, "title": f.title,
                              "source": sources.get(f.fingerprint, "")}
    cutoff = (today - timedelta(days=CARRY_OVER_DAYS)).isoformat()
    for fp, prev in seen.items():
        if fp not in out and prev.get("last_seen", "") >= cutoff and _covered(str(prev.get("source", "")), skipped):
            out[fp] = prev
    return out


def accept(state_dir: Path, fps: list[str], reason: str, days: int, today: date, known: dict) -> int:
    if not reason.strip():
        raise ValueError("reason is required")
    if not 1 <= days <= 365:
        raise ValueError("days must be 1..365")
    unknown = [fp for fp in fps if fp not in known]
    if unknown:
        raise ValueError(f"unknown fingerprints: {unknown[:3]}")
    ensure_dir(state_dir)
    path = state_dir / "baseline.json"
    base = read_json(path, {"accepted": {}})
    acc = base.setdefault("accepted", {})
    until = (today + timedelta(days=days)).isoformat()
    lines = []
    for fp in fps:
        acc[fp] = {"until": until, "reason": reason.strip()[:200],
                                "title": known[fp].get("title", ""), "accepted_at": today.isoformat()}
        lines.append(json.dumps({"fingerprint": fp, "until": until, "reason": reason.strip()[:200],
                                 "at": today.isoformat()}, ensure_ascii=False) + "\n")
    write_json(path, base)  # log only after the baseline took effect
    fd = os.open(state_dir / "accept.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as log:
        log.writelines(lines)
    return len(fps)

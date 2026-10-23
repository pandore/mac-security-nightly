"""seen.json (written nightly) = what was already shown; baseline.json (msec accept only) = what is accepted."""
import json
import os
from datetime import date, timedelta
from pathlib import Path

from .state import read_json, write_json


def classify(findings, seen: dict, accepted: dict, today: date):
    """-> (new, open_items, accepted_now, resolved_fingerprints)."""
    new, open_items, acc, current = [], [], [], set()
    for f in findings:
        fp = f.fingerprint
        current.add(fp)
        a = accepted.get(fp)
        if a and date.fromisoformat(a["until"]) >= today:
            acc.append(f)
        elif a or fp not in seen:          # expired acceptance or never shown
            new.append(f)
        else:
            open_items.append(f)
    return new, open_items, acc, sorted(set(seen) - current)


def update_seen(seen: dict, findings, today: date) -> dict:
    """Resolved items drop out, so a reappearance counts as new."""
    out = {}
    for f in findings:
        prev = seen.get(f.fingerprint, {})
        out[f.fingerprint] = {"first_seen": prev.get("first_seen", today.isoformat()),
                              "last_seen": today.isoformat(), "severity": f.severity, "title": f.title}
    return out


def accept(state_dir: Path, fps: list[str], reason: str, days: int, today: date, known: dict) -> int:
    if not reason.strip():
        raise ValueError("reason is required")
    if not 1 <= days <= 365:
        raise ValueError("days must be 1..365")
    unknown = [fp for fp in fps if fp not in known]
    if unknown:
        raise ValueError(f"unknown fingerprints: {unknown[:3]}")
    path = state_dir / "baseline.json"
    base = read_json(path, {"accepted": {}})
    until = (today + timedelta(days=days)).isoformat()
    fd = os.open(state_dir / "accept.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as log:
        for fp in fps:
            base["accepted"][fp] = {"until": until, "reason": reason.strip()[:200],
                                    "title": known[fp].get("title", ""), "accepted_at": today.isoformat()}
            log.write(json.dumps({"fingerprint": fp, "until": until, "reason": reason.strip()[:200],
                                  "at": today.isoformat()}, ensure_ascii=False) + "\n")
    write_json(path, base)
    return len(fps)

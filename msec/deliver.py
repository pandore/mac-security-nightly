"""Deliver at most once per run, never before deliver_after. Adapters receive only template text."""
from datetime import datetime, timedelta

from . import state, summary
from .runner import SAFE_PATH, run

GRACE = timedelta(hours=2)
STALE_RUNNING = timedelta(hours=3)
MISSING_TEXT = "⚠ Нічна перевірка мака не відпрацювала. Деталі: msec status"


def notify_macos(text: str) -> bool:
    # text goes in as argv, so it can never become AppleScript code
    script = 'on run argv\ndisplay notification (item 1 of argv) with title "Mac security"\nend run'
    return run(["/usr/bin/osascript", "-e", script, text], env={"PATH": SAFE_PATH}, timeout=30).ok


ADAPTERS = {"macos-notify": notify_macos}


def _aware(value) -> datetime | None:
    """Parse an aware ISO timestamp, or None. Never raises."""
    try:
        dt = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return dt if dt.utcoffset() is not None else None


def decide(run_state, now: datetime, deliver_after: str) -> str:
    hh, mm = map(int, deliver_after.split(":"))
    after = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if now < after:
        return "wait"
    if not isinstance(run_state, dict):
        run_state = None
    if run_state is None:
        return "missing" if now >= after + GRACE else "wait"
    if run_state.get("delivered_at"):
        return "done"
    status = run_state.get("status")
    if status == "complete":
        return "send"              # a late completion beats an earlier "missing" alert
    if run_state.get("alerted_missing_at"):
        return "done"
    if status == "running":
        started = _aware(run_state.get("started_at"))
        if started is None:
            return "missing"
        return "missing" if now - started > STALE_RUNNING else "wait"
    return "missing"


def deliver(cfg, now: datetime | None = None, adapters: dict | None = None) -> int:
    adapters = adapters or ADAPTERS
    now = now or state.now(cfg.timezone)
    rid = state.run_id(now)
    runs = state.Runs(cfg.state_dir)
    action = decide(runs.get(rid), now, cfg.deliver_after)
    if action in ("wait", "done"):
        return 0
    field, text = "alerted_missing_at", MISSING_TEXT
    if action == "send":
        field = "delivered_at"     # also after a tampered summary, so it is not retried forever
        try:
            text = summary.message(state.read_json(cfg.state_dir / "reports" / rid / "summary.json") or {})
        except (ValueError, OSError):
            text = MISSING_TEXT    # unreadable or tampered summary: alert instead of sending its content
    ok = True
    if text:
        for name in cfg.adapters:
            ok = adapters[name](text) and ok
    if ok:
        runs.mark(rid, field, now)
    return 0 if ok else 1

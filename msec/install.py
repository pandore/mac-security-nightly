"""Render user LaunchAgent plists with plistlib (no string templates) and load them with launchctl."""
import plistlib
from pathlib import Path

from . import state
from .runner import SAFE_PATH, run

LABELS = ("com.msec.nightly", "com.msec.deliver")
NIGHTLY_AT = (4, 0)
PYTHON = Path("/opt/homebrew/bin/python3")


def plist_for(label: str, python: Path, entry: Path, args: list[str], times, log_dir: Path) -> dict:
    for p in (python, entry, log_dir):
        if not Path(p).is_absolute():
            raise ValueError(f"absolute path required: {p}")
    log = str(log_dir / f"{label}.log")
    return {"Label": label, "ProgramArguments": [str(python), "-I", str(entry), *args],
            "StartCalendarInterval": [{"Hour": h, "Minute": m} for h, m in times],
            "StandardOutPath": log, "StandardErrorPath": log,
            "ProcessType": "Background", "LowPriorityIO": True, "Nice": 10}


def delivery_times(deliver_after: str) -> list[tuple[int, int]]:
    h, m = map(int, deliver_after.split(":"))
    later = min(h * 60 + m + 150, 23 * 60 + 59)
    return [(h, m), (later // 60, later % 60)]


def install(cfg, entry: Path, launch_agents: Path, uid: int, dry_run: bool = False) -> int:
    log_dir = cfg.state_dir / "logs"
    jobs = {"com.msec.nightly": (["nightly"], [NIGHTLY_AT]),
            "com.msec.deliver": (["deliver"], delivery_times(cfg.deliver_after))}
    for label, (args, times) in jobs.items():
        plist = plist_for(label, PYTHON, entry, args, times, log_dir)
        target = launch_agents / f"{label}.plist"
        print(f"{'would write' if dry_run else 'writing'} {target}: {plist['ProgramArguments']} at {times}")
        if dry_run:
            continue
        state.ensure_dir(log_dir)
        launch_agents.mkdir(parents=True, exist_ok=True)
        state.write_text(target, plistlib.dumps(plist).decode())
        env = {"PATH": SAFE_PATH}
        run(["/bin/launchctl", "bootout", f"gui/{uid}/{label}"], env=env, timeout=30)   # ok if not loaded
        r = run(["/bin/launchctl", "bootstrap", f"gui/{uid}", str(target)], env=env, timeout=30)
        if not r.ok:
            print(f"launchctl bootstrap failed for {label}: {r.stderr.strip()}")
            return 1
    return 0

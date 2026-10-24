"""Shared context for checks. Checks read files directly and run tools only through Ctx.cmd."""
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from ..findings import clean, not_scanned
from ..runner import CmdResult, run, scanner_env


@dataclass(frozen=True)
class Ctx:
    home: Path
    scan_roots: tuple[Path, ...]
    sandbox: Path
    uid: int
    system_dirs: bool = True

    def cmd(self, argv, timeout: float = 120, stdin_text: str | None = None,
            real_home: bool = False) -> CmdResult:
        env = scanner_env(self.sandbox)
        if real_home:
            env["HOME"] = str(self.home)
        t = time.monotonic()
        r = run(argv, env=env, timeout=timeout, stdin_text=stdin_text)
        log_cmd(r, time.monotonic() - t)
        return r


def log_cmd(r: CmdResult, secs: float) -> None:
    """Slow or failed commands go to stderr (the LaunchAgent log): the only record of why a scanner went quiet."""
    if r.timed_out or r.missing or r.rc not in (0, 1) or secs >= 5:
        name = " ".join([Path(r.argv[0]).name, *r.argv[1:2]])
        state = "timed out" if r.timed_out else "missing" if r.missing else f"rc={r.rc}"
        print(f"msec: {name}: {state}, {secs:.0f}s, stdout {len(r.stdout)} B, stderr: {clean(r.stderr[-400:], 400)}",
              file=sys.stderr, flush=True)


def guard(name: str, fn, *args) -> list:
    """Run one (sub-)check; an exception becomes not_scanned instead of hiding its siblings."""
    try:
        out = fn(*args)
    except PermissionError as e:
        return [not_scanned(name, f"permission denied: {e.filename}")]
    except Exception as e:
        return [not_scanned(name, f"check crashed: {type(e).__name__}: {e}")]
    return out if isinstance(out, list) else [out]

"""Run external commands with a fixed argv, a scrubbed environment and a timeout. Never uses a shell."""
import os
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path

SAFE_PATH = "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"


@dataclass(frozen=True)
class CmdResult:
    argv: tuple[str, ...]
    rc: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    missing: bool = False

    @property
    def ok(self) -> bool:
        return self.rc == 0


def _text(b) -> str:
    # TimeoutExpired carries bytes even with text=True
    if b is None:
        return ""
    return b if isinstance(b, str) else b.decode("utf-8", "replace")


def scanner_env(sandbox_home: Path) -> dict[str, str]:
    """Env for scanners: nothing inherited, caches and temp files inside the state dir."""
    for sub in ("tmp", "cache", "config"):
        (sandbox_home / sub).mkdir(mode=0o700, parents=True, exist_ok=True)
    return {
        "PATH": SAFE_PATH,
        "HOME": str(sandbox_home),
        "TMPDIR": str(sandbox_home / "tmp"),
        "XDG_CACHE_HOME": str(sandbox_home / "cache"),
        "XDG_CONFIG_HOME": str(sandbox_home / "config"),
        "LANG": "en_US.UTF-8",
        "NO_COLOR": "1",
        "HOMEBREW_NO_AUTO_UPDATE": "1",
        "HOMEBREW_NO_ANALYTICS": "1",
        "HOMEBREW_NO_ENV_HINTS": "1",
    }


def run(argv, *, env: dict[str, str], timeout: float, stdin_text: str | None = None,
        cwd: Path | None = None) -> CmdResult:
    argv = tuple(str(a) for a in argv)
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace", env=env, cwd=cwd,
                                start_new_session=True)
    except FileNotFoundError:
        return CmdResult(argv, None, "", "", missing=True)
    except OSError as e:   # e.g. PermissionError on a non-executable path
        return CmdResult(argv, None, "", str(e), missing=True)
    try:
        out, err = proc.communicate(input=stdin_text, timeout=timeout)
        return CmdResult(argv, proc.returncode, out, err)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)  # whole group: scanners spawn helpers that hold the pipes
        except ProcessLookupError:
            pass
        out, err = proc.communicate()
        return CmdResult(argv, None, _text(out), _text(err), timed_out=True)

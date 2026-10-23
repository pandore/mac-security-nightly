"""Run external commands with a fixed argv, a scrubbed environment and a timeout. Never uses a shell."""
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
        p = subprocess.run(argv, input=stdin_text, capture_output=True, text=True,
                           env=env, timeout=timeout, cwd=cwd, shell=False)
        return CmdResult(argv, p.returncode, p.stdout, p.stderr)
    except FileNotFoundError:
        return CmdResult(argv, None, "", "", missing=True)
    except subprocess.TimeoutExpired as e:
        return CmdResult(argv, None, _text(e.stdout), _text(e.stderr), timed_out=True)

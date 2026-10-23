"""Shared context for checks. Checks read files directly and run tools only through Ctx.cmd."""
from dataclasses import dataclass
from pathlib import Path

from ..findings import not_scanned
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
        return run(argv, env=env, timeout=timeout, stdin_text=stdin_text)


def guard(name: str, fn, *args) -> list:
    """Run one (sub-)check; an exception becomes not_scanned instead of hiding its siblings."""
    try:
        out = fn(*args)
    except PermissionError as e:
        return [not_scanned(name, f"permission denied: {e.filename}")]
    except Exception as e:
        return [not_scanned(name, f"check crashed: {type(e).__name__}: {e}")]
    return out if isinstance(out, list) else [out]

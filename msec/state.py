"""Atomic, symlink-refusing writes under the state dir, and per-day run state."""
import fcntl
import json
import os
import tempfile
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo


def ensure_dir(p: Path) -> Path:
    if p.is_symlink():
        raise RuntimeError(f"refusing symlinked dir {p}")
    p.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(p, 0o700)
    return p


def write_text(path: Path, text: str) -> None:
    ensure_dir(path.parent)
    if path.is_symlink():
        raise RuntimeError(f"refusing to write through symlink {path}")
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def write_json(path: Path, data) -> None:
    write_text(path, json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n")


def read_json(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default


@contextmanager
def locked(path: Path, blocking: bool = True):
    """Exclusive flock on a 0600 lock file; yields False when non-blocking and already held."""
    ensure_dir(path.parent)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except BlockingIOError:
            yield False
            return
        yield True
    finally:
        os.close(fd)


def now(tz: str) -> datetime:
    return datetime.now(ZoneInfo(tz))


def run_id(at: datetime) -> str:
    return at.date().isoformat()


class Runs:
    """runs/<run-id>.json — status running|complete|failed, plus delivered_at / alerted_missing_at."""

    def __init__(self, state_dir: Path):
        ensure_dir(state_dir)
        self.dir = ensure_dir(state_dir / "runs")

    def path(self, rid: str) -> Path:
        return self.dir / f"{rid}.json"

    def get(self, rid: str) -> dict | None:
        return read_json(self.path(rid))

    def start(self, rid: str, at: datetime, force: bool = False) -> bool:
        cur = self.get(rid)
        if cur and cur.get("status") == "complete" and not force:
            return False
        write_json(self.path(rid), {"run_id": rid, "status": "running", "started_at": at.isoformat()})
        return True

    def finish(self, rid: str, at: datetime, status: str, error: str = "") -> dict:
        cur = self.get(rid) or {"run_id": rid}
        cur.update(status=status, finished_at=at.isoformat(), error=error[:500])
        write_json(self.path(rid), cur)
        return cur

    def mark(self, rid: str, field: str, at: datetime) -> None:
        cur = self.get(rid) or {"run_id": rid, "status": "missing"}
        cur[field] = at.isoformat()
        write_json(self.path(rid), cur)

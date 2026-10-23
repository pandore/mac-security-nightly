import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from msec.checks import Ctx
from msec.runner import CmdResult


@dataclass(frozen=True)
class FakeCtx(Ctx):
    """responses: full argv tuple or argv[0] -> (rc, stdout, stderr) | "missing" | "timeout"."""
    responses: dict = field(default_factory=dict)
    calls: list = field(default_factory=list)

    def cmd(self, argv, timeout=120, stdin_text=None, real_home=False):
        argv = tuple(str(a) for a in argv)
        self.calls.append((argv, real_home))
        key = argv if argv in self.responses else argv[0]
        resp = self.responses.get(key, "missing")
        if isinstance(resp, list):      # sequence: consumed in order, last one repeats
            resp = resp.pop(0) if len(resp) > 1 else resp[0]
        if resp == "missing":
            return CmdResult(argv, None, "", "", missing=True)
        if resp == "timeout":
            return CmdResult(argv, None, "", "", timed_out=True)
        rc, out, err = resp
        return CmdResult(argv, rc, out, err)


def tmp_ctx(responses=None) -> FakeCtx:
    base = Path(tempfile.mkdtemp())
    home, root = base / "home", base / "repos"
    home.mkdir()
    root.mkdir()
    return FakeCtx(home=home, scan_roots=(root,), sandbox=base / "sandbox", uid=501,
                   system_dirs=False, responses=responses or {})

"""Autorun: launchd plists, Background Task Management records, crontab, shell rc files."""
import hashlib
import os
import plistlib
import re
import shlex
from pathlib import Path

from ..findings import Finding, not_scanned, result

INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "env", "osascript", "perl",
                "ruby", "node", "bun", "deno", "php", "swift", "lua", "Rscript"}
PY_NAME = re.compile(r"(python|pypy)[0-9.]*")


def is_script(prog: str, args: list) -> bool:
    base = os.path.basename(prog)
    return (base in INTERPRETERS or bool(PY_NAME.fullmatch(base))
            or (len(args) > 1 and args[1] in ("-c", "-e")))


RC_FILES = (".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bash_profile", ".bashrc", ".profile")
BTM_SKIP_TYPES = ("legacy agent", "legacy daemon")   # plists are covered by scan_launchd
REC = re.compile(r"^\s*#\d+:\s*$")
KV = re.compile(r"^\s*([A-Za-z][A-Za-z ]*?):\s?(.*)$")
UID_HDR = re.compile(r"Records for UID (-?\d+)")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def signer(ctx, path: str) -> str:
    """Team ID, 'apple', 'adhoc' or 'unsigned'."""
    r = ctx.cmd(["/usr/bin/codesign", "-dv", "--verbose=2", path], timeout=30)
    m = re.search(r"^TeamIdentifier=(\S+)", r.stderr, re.M)
    if m and m.group(1) != "not set":
        return m.group(1)
    if "Authority=Software Signing" in r.stderr:
        return "apple"
    if "Signature=adhoc" in r.stderr:
        return "adhoc"
    return "unsigned"


def scan_launchd(ctx, dirs) -> list:
    findings, denied = [], []
    for d in dirs:
        try:
            with os.scandir(d) as it:
                entries = sorted(Path(e.path) for e in it if e.name.endswith(".plist"))
        except FileNotFoundError:
            continue
        except PermissionError:
            denied.append(str(d))
            continue
        for p in entries:
            try:
                data = plistlib.loads(p.read_bytes())
                if not isinstance(data, dict) or not isinstance(data.get("ProgramArguments", []), list):
                    raise ValueError("unexpected plist shape")
            except PermissionError:
                denied.append(str(p))
                continue
            except Exception:
                findings.append(Finding("persistence.launchd", "persistence", "medium",
                                        f"Unparseable launchd plist {p}", {"plist": str(p), "unparseable": True}))
                continue
            args = [str(a) for a in data.get("ProgramArguments") or []]
            prog = str(data.get("Program") or (args[0] if args else ""))
            sig = signer(ctx, prog) if prog else "unsigned"
            script = is_script(prog, args)
            label = str(data.get("Label", p.stem))
            domain = f"gui/{ctx.uid}" if d == ctx.home / "Library/LaunchAgents" else "system"
            findings.append(Finding(
                "persistence.launchd", "persistence",
                "critical" if script or sig in ("unsigned", "adhoc") else "medium",
                f"launchd {label} → {prog}{' (script)' if script else ''} [{sig}]",
                {"plist": str(p), "program": prog, "args": _sha("\0".join(args).encode()), "signer": sig},
                details={"label": label, "dir": str(d)},
                fix=(f"launchctl bootout {domain} {shlex.quote(str(p))}",)))
    out = [result("persistence.launchd", findings)]
    if denied:
        out.append(not_scanned("persistence.launchd.partial", f"{len(denied)} paths unreadable, e.g. {denied[0]}"))
    return out


def parse_btm(text: str, uid: int) -> list[dict]:
    recs, cur, mine = [], None, False
    for line in text.splitlines():
        hdr = UID_HDR.search(line)
        if hdr:
            mine, cur = int(hdr.group(1)) == uid, None
            continue
        if not mine:
            continue
        if REC.match(line):
            cur = {}
            recs.append(cur)
            continue
        kv = KV.match(line)
        if cur is not None and kv:
            cur[kv.group(1).strip()] = kv.group(2).strip()
    return recs


def scan_btm(ctx):
    r = ctx.cmd(["/usr/bin/sfltool", "dumpbtm"], timeout=300)
    if r.missing or r.timed_out or r.rc != 0:
        return not_scanned("persistence.btm", "sfltool dumpbtm failed or timed out")
    if not re.search(rf"Records for UID {ctx.uid}\b", r.stdout):
        return not_scanned("persistence.btm", "sfltool output had no records section for this user")
    out = []
    for rec in parse_btm(r.stdout, ctx.uid):
        typ = rec.get("Type", "")
        if not rec.get("Disposition", "").startswith("[enabled") or typ.startswith(BTM_SKIP_TYPES):
            continue
        team, dev = rec.get("Team Identifier", ""), rec.get("Developer Name", "(null)")
        ident = rec.get("Identifier", "")
        exe = rec.get("Executable Path") or rec.get("URL", "")
        out.append(Finding(
            "persistence.btm", "persistence",
            "critical" if not team and dev in ("(null)", "Unknown Developer", "") else "medium",
            f"Background item {rec.get('Name', ident)} ({typ}) by {dev}",
            {"type": typ, "identifier": ident, "exe": exe, "team": team}, details={"developer": dev}))
    return result("persistence.btm", out)


def scan_cron(ctx):
    r = ctx.cmd(["/usr/bin/crontab", "-l"], timeout=30)
    if r.rc != 0:
        if "no crontab" in r.stderr:
            return result("persistence.cron", [])
        return not_scanned("persistence.cron", "crontab -l failed")
    out = []
    for line in r.stdout.splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(Finding("persistence.cron", "persistence", "critical", f"crontab entry: {s}",
                               {"line": _sha(s.encode())}, fix=("crontab -e",)))
    return result("persistence.cron", out)


def scan_rc(ctx):
    out = []
    for name in RC_FILES:
        p = ctx.home / name
        try:
            data = p.read_bytes()
        except FileNotFoundError:
            continue
        except PermissionError:
            return not_scanned("persistence.rc", f"cannot read {p}")
        out.append(Finding("persistence.rc", "persistence", "medium", f"Shell startup file {p} has new content",
                           {"file": str(p), "sha256": _sha(data)}))
    return result("persistence.rc", out)


def run(ctx) -> list:
    dirs = [ctx.home / "Library/LaunchAgents"]
    if ctx.system_dirs:
        dirs += [Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons")]
    return [*scan_launchd(ctx, dirs), scan_btm(ctx), scan_cron(ctx), scan_rc(ctx)]

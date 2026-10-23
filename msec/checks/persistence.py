"""Autorun: launchd plists, Background Task Management records, crontab, shell rc files."""
import hashlib
import os
import plistlib
import re
import shlex
from pathlib import Path

from ..findings import Finding, not_scanned, result
from . import guard

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
    if not os.path.isabs(path):     # never hand codesign a relative path or something that looks like a flag
        return "unsigned"
    r = ctx.cmd(["/usr/bin/codesign", "-dv", "--verbose=2", path], timeout=30)
    err = r.stderr
    if re.search(r"^Signature=adhoc\s*$", err, re.M):
        return "adhoc"
    if re.search(r"^Authority=.*Software Signing\s*$", err, re.M):
        return "apple"
    m = re.search(r"^TeamIdentifier=(.+?)\s*$", err, re.M)
    if m and m.group(1) != "not set":
        return m.group(1)
    return "unsigned"


def _script_key(args: list) -> dict:
    """Hash of the script an interpreter runs: first absolute regular-file argument (covers env/flags)."""
    path = next((a for a in args[1:] if os.path.isabs(a) and os.path.isfile(a)), None)
    if path is None:
        return {}
    try:
        return {"script": _sha(Path(path).read_bytes())}
    except OSError:
        return {"script": "unreadable"}


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
            raw = b""
            try:
                raw = p.read_bytes()
                data = plistlib.loads(raw)
                if not isinstance(data, dict) or not isinstance(data.get("ProgramArguments", []), list):
                    raise ValueError("unexpected plist shape")
            except PermissionError:
                denied.append(str(p))
                continue
            except Exception:
                findings.append(Finding("persistence.launchd", "persistence", "medium",
                                        f"Unparseable launchd plist {p}",
                                        {"path": str(p), "plist": _sha(raw), "unparseable": True}))
                continue
            args = [str(a) for a in data.get("ProgramArguments") or []]
            prog = str(data.get("Program") or (args[0] if args else ""))
            sig = signer(ctx, prog)
            script = is_script(prog, args)
            # whole-plist hash: EnvironmentVariables (DYLD_INSERT_LIBRARIES), WatchPaths, KeepAlive...
            key = {"path": str(p), "plist": _sha(raw), "program": prog,
                   "args": _sha("\0".join(args).encode()), "signer": sig}
            if script:
                key.update(_script_key(args))
            label = str(data.get("Label", p.stem))
            domain = f"gui/{ctx.uid}" if d == ctx.home / "Library/LaunchAgents" else "system"
            findings.append(Finding(
                "persistence.launchd", "persistence",
                "critical" if script or sig in ("unsigned", "adhoc") else "medium",
                f"launchd {label} → {prog}{' (script)' if script else ''} [{sig}]",
                key,
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
    uid_re = rf"Records for UID {ctx.uid}\b"
    for _ in range(2):      # sfltool occasionally fails transiently in the nightly: retry once
        r = ctx.cmd(["/usr/bin/sfltool", "dumpbtm"], timeout=300)
        if not (r.missing or r.timed_out or r.rc != 0) and re.search(uid_re, r.stdout):
            break
    else:
        if r.timed_out:
            why = "timed out twice"
        elif r.missing:
            why = "missing"
        elif r.rc != 0:
            why = f"failed twice (rc={r.rc})"
        else:
            return not_scanned("persistence.btm", "sfltool output had no records section for this user")
        return not_scanned("persistence.btm", f"sfltool dumpbtm {why}")
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
    return [*guard("persistence.launchd", scan_launchd, ctx, dirs), *guard("persistence.btm", scan_btm, ctx),
            *guard("persistence.cron", scan_cron, ctx), *guard("persistence.rc", scan_rc, ctx)]

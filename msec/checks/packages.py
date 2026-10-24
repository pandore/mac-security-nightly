"""Packages and updates: brew vulns, osv-scanner, grype on global npm, npm outdated, softwareupdate, worm IOC files."""
import functools
import json
import re
import shlex
from pathlib import Path

from ..findings import Finding, not_scanned, result
from . import guard

BREW = "/opt/homebrew/bin/brew"
OSV = "/opt/homebrew/bin/osv-scanner"
GRYPE = "/opt/homebrew/bin/grype"
NPM = "/opt/homebrew/bin/npm"
IOC_NAMES = ("bun_environment.js", "truffleSecrets.json", "setup_bun.js")


class _Shape(Exception):
    pass


def _items(v) -> list:
    """A JSON list field that must hold only objects; None/missing counts as empty."""
    if v is None:
        return []
    if not isinstance(v, list) or not all(isinstance(x, dict) for x in v):
        raise _Shape
    return v


def _obj(v) -> dict:
    if v is None:
        return {}
    if not isinstance(v, dict):
        raise _Shape
    return v


def _shape_guarded(check: str):
    """Unexpected JSON shapes become not_scanned, never an exception."""
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(ctx):
            try:
                return fn(ctx)
            except _Shape:
                return [not_scanned(check, "unexpected output shape")]
        return wrapper
    return deco


def _json(r, check: str, key: str | None = None):
    """-> (data, None) or (None, not_scanned). Scanners exit 1 when they find things, so rc is ignored.
    `key`: a field the tool always prints, even when clean; output without it is a failure, not a clean result."""
    if r.missing:
        return None, not_scanned(check, "tool not installed")
    if r.timed_out:
        return None, not_scanned(check, "timed out")
    if not r.stdout.strip():
        if r.rc not in (0, None) or key:
            return None, not_scanned(check, f"no output (rc={r.rc})")
        return {}, None
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return None, not_scanned(check, f"unexpected output (rc={r.rc})")
    if not isinstance(data, dict) or (key and key not in data):
        return None, not_scanned(check, f"unexpected output (rc={r.rc})")
    return data, None


@_shape_guarded("packages.brew")
def brew_vulns(ctx) -> list:
    data, err = _json(ctx.cmd([BREW, "vulns", "--json"], timeout=900, real_home=True), "packages.brew")
    if err:
        return [err]
    out = []
    for fm in _items(data.get("findings")):
        formula = str(fm.get("formula", ""))
        for v in _items(fm.get("vulnerabilities")):
            fixed = [str(x) for x in v.get("fixed_versions") or []]
            raw = str(v.get("severity", "UNKNOWN")).upper()
            sev = "high" if fixed and raw in ("HIGH", "CRITICAL") else "medium" if fixed else "info"
            out.append(Finding("packages.brew", "packages", sev,
                               f"{formula} {fm.get('version', '')}: {v.get('id')} {raw} — {v.get('summary', '')}",
                               {"formula": formula, "id": str(v.get("id"))},
                               details={"fixed": ", ".join(fixed)[:200]},
                               fix=(f"brew upgrade {shlex.quote(formula)}",) if fixed else ()))
    res = [result("packages.brew", out)]
    if data.get("complete") is False:
        skipped = data.get("skipped_formulae")
        res.append(not_scanned("packages.brew.partial",
                               f"{len(skipped) if isinstance(skipped, list) else 'some'} formulae skipped by brew vulns"))
    return res


@_shape_guarded("packages.osv")
def osv(ctx) -> list:
    out, errs, scanned = [], [], 0
    for root in ctx.scan_roots:
        scanned += 1
        data, err = _json(ctx.cmd([OSV, "scan", "source", "-r", str(root), "--format", "json"], timeout=1800),
                          "packages.osv", key="results")
        if err:
            errs.append(not_scanned("packages.osv.partial", err.reason))
            continue
        for res in _items(data.get("results")):
            src = str(_obj(res.get("source")).get("path", ""))
            for pk in _items(res.get("packages")):
                pkg = _obj(pk.get("package"))
                name, version = f"{pkg.get('ecosystem')}/{pkg.get('name')}", str(pkg.get("version"))
                ids, score = set(), 0.0
                for g in _items(pk.get("groups")):
                    ids.update(str(i) for i in g.get("ids") or [] if i)
                    try:
                        score = max(score, float(g.get("max_severity") or 0))
                    except ValueError:
                        pass
                if not ids:
                    continue
                ids = sorted(ids)
                mal = next((i for i in ids if i.startswith("MAL-")), None)
                title = (f"{name} {version}: MALICIOUS {mal} in {src}" if mal else
                         f"{name} {version}: {len(ids)} advisories (max CVSS {score:.1f}) in {src}")
                out.append(Finding("packages.osv", "ioc" if mal else "packages", "critical" if mal else "info", title,
                                   {"source": src, "package": name, "version": version},
                                   details={"ids": ", ".join(ids[:10]), "max_score": score}))
    if errs and len(errs) == scanned:   # every root/target failed: the check itself is not scanned
        return [not_scanned("packages.osv", errs[0].reason)]
    return [result("packages.osv", out), *errs]


@_shape_guarded("packages.grype")
def grype(ctx) -> list:
    out, errs, scanned = [], [], 0
    for target in (Path("/opt/homebrew/lib/node_modules"), ctx.home / ".npm/_npx"):
        if not target.is_dir():
            continue
        scanned += 1
        data, err = _json(ctx.cmd([GRYPE, f"dir:{target}", "-o", "json", "--quiet"], timeout=1800), "packages.grype", key="matches")
        if err:
            errs.append(not_scanned("packages.grype.partial", err.reason))
            continue
        agg: dict = {}   # (package, version) -> [ids, fixable_high, first_location]
        for m in _items(data.get("matches")):
            v, a = _obj(m.get("vulnerability")), _obj(m.get("artifact"))
            locs = _items(a.get("locations"))
            e = agg.setdefault((str(a.get("name")), str(a.get("version"))),
                               [[], 0, str(locs[0].get("path", "")) if locs else ""])
            e[0].append(str(v.get("id")))
            if _obj(v.get("fix")).get("state") == "fixed" and str(v.get("severity", "")).lower() in ("high", "critical"):
                e[1] += 1
        for (name, version), (ids, fixable, loc) in agg.items():
            out.append(Finding("packages.grype", "packages", "high" if fixable else "info",
                               f"{name} {version}: {len(ids)} vulns, {fixable} fixable high/critical",
                               {"target": str(target), "package": name, "version": version},
                               details={"ids": ", ".join(ids[:10]), "location": loc}))
    if errs and len(errs) == scanned:   # every root/target failed: the check itself is not scanned
        return [not_scanned("packages.grype", errs[0].reason)]
    return [result("packages.grype", out), *errs]


def npm_outdated(ctx):
    data, err = _json(ctx.cmd([NPM, "-g", "outdated", "--json"], timeout=300), "updates.npm")
    if err:
        return err
    out = [Finding("updates.npm", "updates", "info", f"npm -g {name} {v.get('current')} → {v.get('latest')}",
                   {"package": str(name), "latest": str(v.get("latest"))},
                   fix=(f"npm i -g {shlex.quote(str(name) + '@' + str(v.get('latest')))}",))
           for name, v in data.items() if isinstance(v, dict) and v.get("latest")]
    return result("updates.npm", out)


def softwareupdate(ctx):
    r = ctx.cmd(["/usr/sbin/softwareupdate", "-l"], timeout=600)
    if r.missing or r.timed_out:
        return not_scanned("updates.macos", "softwareupdate -l failed or timed out")
    if r.rc != 0:
        return not_scanned("updates.macos", f"softwareupdate -l failed (rc={r.rc})")
    labels = re.findall(r"^\*\s*Label:\s*(.+?)\s*$", r.stdout + "\n" + r.stderr, re.M)
    return result("updates.macos", [
        Finding("updates.macos", "updates", "medium", f"macOS update available: {label}", {"label": label},
                fix=(f"softwareupdate -i {shlex.quote(label)}",)) for label in labels])


def ioc_files(ctx):
    st = ctx.cmd(["/usr/bin/mdutil", "-s", "/System/Volumes/Data"], timeout=30)
    if not st.ok or "Indexing enabled" not in st.stdout:
        return not_scanned("ioc.files", "Spotlight indexing is off, so IOC file search cannot run")
    out = []
    for name in IOC_NAMES:
        r = ctx.cmd(["/usr/bin/mdfind", "-onlyin", str(ctx.home), f"kMDItemFSName == '{name}'"], timeout=120)
        if not r.ok:
            return not_scanned("ioc.files", "Spotlight query failed")
        for path in filter(None, (line.strip() for line in r.stdout.splitlines())):
            out.append(Finding("ioc.files", "ioc", "critical", f"Worm IOC file {name}: {path}", {"path": path}))
    return result("ioc.files", out)


def run(ctx) -> list:
    subs = (("packages.brew", brew_vulns), ("packages.osv", osv), ("packages.grype", grype),
            ("updates.npm", npm_outdated), ("updates.macos", softwareupdate), ("ioc.files", ioc_files))
    return [r for name, fn in subs for r in guard(name, fn, ctx)]

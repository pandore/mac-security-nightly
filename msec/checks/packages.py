"""Packages and updates: brew vulns, osv-scanner, grype on global npm, npm outdated, softwareupdate, worm IOC files."""
import functools
import json
import re
import shlex
from pathlib import Path

from ..findings import Finding, not_scanned, result

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


def _json(r, check: str):
    """-> (data, None) or (None, not_scanned). Scanners exit 1 when they find things, so rc is ignored."""
    if r.missing:
        return None, not_scanned(check, "tool not installed")
    if r.timed_out:
        return None, not_scanned(check, "timed out")
    try:
        data = json.loads(r.stdout) if r.stdout.strip() else {}
    except json.JSONDecodeError:
        return None, not_scanned(check, f"unexpected output (rc={r.rc})")
    if not isinstance(data, dict):
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
    out = []
    for root in ctx.scan_roots:
        data, err = _json(ctx.cmd([OSV, "scan", "source", "-r", str(root), "--format", "json"], timeout=1800),
                          "packages.osv")
        if err:
            return [err]
        for res in _items(data.get("results")):
            src = str(_obj(res.get("source")).get("path", ""))
            for pk in _items(res.get("packages")):
                pkg = _obj(pk.get("package"))
                name = f"{pkg.get('ecosystem')}/{pkg.get('name')}"
                for g in _items(pk.get("groups")):
                    ids = sorted(str(i) for i in g.get("ids") or [] if i)
                    if not ids:
                        continue
                    if any(i.startswith("MAL-") for i in ids):
                        sev, cat = "critical", "ioc"
                    else:
                        try:
                            score = float(g.get("max_severity") or 0)
                        except ValueError:
                            score = 0.0
                        sev, cat = ("high" if score >= 7.0 else "info"), "packages"
                    primary = next((i for i in ids if i.startswith("MAL-")), ids[0]) if sev == "critical" \
                        else next((i for i in ids if i.startswith("CVE-")), ids[0])
                    out.append(Finding("packages.osv", cat, sev,
                                       f"{name} {pkg.get('version')}: {', '.join(ids[:3])} in {src}",
                                       {"source": src, "package": name, "version": str(pkg.get("version")),
                                        "id": primary}))
    return [result("packages.osv", out)]


@_shape_guarded("packages.grype")
def grype(ctx) -> list:
    out = []
    for target in (Path("/opt/homebrew/lib/node_modules"), ctx.home / ".npm/_npx"):
        if not target.is_dir():
            continue
        data, err = _json(ctx.cmd([GRYPE, f"dir:{target}", "-o", "json", "--quiet"], timeout=1800), "packages.grype")
        if err:
            return [err]
        for m in _items(data.get("matches")):
            v, a = _obj(m.get("vulnerability")), _obj(m.get("artifact"))
            raw = str(v.get("severity", "")).lower()
            fixed = _obj(v.get("fix")).get("state") == "fixed"
            locs = _items(a.get("locations"))
            loc = locs[0].get("path", "") if locs else ""
            out.append(Finding("packages.grype", "packages", "high" if fixed and raw in ("high", "critical") else "info",
                               f"{a.get('name')} {a.get('version')}: {v.get('id')} {raw}{' (fix available)' if fixed else ''}",
                               {"target": str(target), "package": str(a.get("name")),
                                "version": str(a.get("version")), "id": str(v.get("id"))},
                               details={"location": str(loc)}))
    return [result("packages.grype", out)]


def npm_outdated(ctx):
    data, err = _json(ctx.cmd([NPM, "-g", "outdated", "--json"], timeout=300), "updates.npm")
    if err:
        return err
    out = [Finding("updates.npm", "updates", "info", f"npm -g {name} {v.get('current')} → {v.get('latest')}",
                   {"package": str(name), "latest": str(v.get("latest"))},
                   fix=(f"npm i -g {shlex.quote(str(name) + '@' + str(v.get('latest')))}",))
           for name, v in data.items() if isinstance(v, dict)]
    return result("updates.npm", out)


def softwareupdate(ctx):
    r = ctx.cmd(["/usr/sbin/softwareupdate", "-l"], timeout=600)
    if r.missing or r.timed_out:
        return not_scanned("updates.macos", "softwareupdate -l failed or timed out")
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
    return [*brew_vulns(ctx), *osv(ctx), *grype(ctx), npm_outdated(ctx), softwareupdate(ctx), ioc_files(ctx)]

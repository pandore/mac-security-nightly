"""msec nightly | deliver | accept | status | install"""
import argparse
import json
import os
import sys
from pathlib import Path

from . import baseline, config, report, state, summary
from . import deliver as deliver_mod
from . import triage as triage_mod
from .checks import Ctx, agents, guard, packages, persistence
from .findings import Finding, clean, not_scanned, result

CHECKS = (persistence.run, agents.run, packages.run)
CONFIG_TEXT = "⚠ msec: конфіг не читається — msec status"


def collect(ctx, checks=CHECKS) -> list:
    results = []
    for fn in checks:   # one broken check must not hide the others
        results.extend(guard(fn.__module__.rsplit(".", 1)[-1], fn, ctx))
    return results


def coverage(results) -> list:
    """Every not_scanned check becomes a medium finding: it alerts once, then sits in the digest."""
    return [result("coverage", [Finding("coverage", "coverage", "medium", f"Not scanned: {r.check} — {r.reason}",
                                        {"check": r.check}) for r in results if r.status == "not_scanned"])]


def _triage(cfg, items, sandbox):
    try:
        return triage_mod.triage(cfg.triage, items, home=Path.home(), cwd=sandbox)
    except Exception as e:      # the deterministic report must not depend on the model step
        return None, f"triage crashed: {type(e).__name__}: {clean(e)}"


def _run(cfg, force: bool, checks) -> bool:
    """One nightly run under the lock. -> False if today's run is already complete."""
    started = state.now(cfg.timezone)
    rid = state.run_id(started)
    runs = state.Runs(cfg.state_dir)
    if not runs.start(rid, started, force):
        print(f"run {rid} already complete")
        return False
    try:
        sandbox = state.ensure_dir(cfg.state_dir / "sandbox")
        roots = tuple(r for r in cfg.scan_roots if r.is_dir())
        results = [not_scanned("config.scan_root", f"scan root is not an existing dir: {r}")
                   for r in cfg.scan_roots if r not in roots]
        results += collect(Ctx(home=Path.home(), scan_roots=roots, sandbox=sandbox, uid=os.getuid()), checks)
        results += coverage(results)
        uniq, sources = {}, {}      # dedupe by fingerprint, first wins; remember which check produced it
        for r in results:
            for f in r.findings:
                uniq.setdefault(f.fingerprint, f)
                sources.setdefault(f.fingerprint, r.check)
        findings = list(uniq.values())
        seen = state.read_json(cfg.state_dir / "seen.json", {})
        accepted = (state.read_json(cfg.state_dir / "baseline.json", {}) or {}).get("accepted", {})
        if not isinstance(accepted, dict):
            accepted = {}
        today = started.date()
        new, open_items, acc, _ = baseline.classify(findings, seen, accepted, today)
        skipped = [r.check for r in results if r.status == "not_scanned"]
        new_seen = baseline.update_seen(seen, findings, today, sources, skipped)
        resolved = sorted(set(seen) - set(new_seen))
        open_crit = [f for f in open_items if f.severity == "critical"]
        tri, tri_err = _triage(cfg, new + open_crit, sandbox)
        day = state.ensure_dir(cfg.state_dir / "reports" / rid)
        state.write_json(day / "findings.json", [f.to_json() for f in findings])
        state.write_text(day / "report.md", report.render(rid, new, open_items, acc, resolved, results, tri, tri_err))
        state.write_json(day / "summary.json", summary.build(rid, new, open_crit, results))
        state.write_json(cfg.state_dir / "seen.json", new_seen)
        runs.finish(rid, state.now(cfg.timezone), "complete")
    except Exception as e:
        runs.finish(rid, state.now(cfg.timezone), "failed", f"{type(e).__name__}: {e}")
        raise
    return True


def nightly(cfg, force: bool = False, checks=CHECKS, do_deliver: bool = True) -> int:
    with state.locked(cfg.state_dir / "nightly.lock", blocking=False) as got:
        if not got:
            print("nightly already running")
            return 0
        if not _run(cfg, force, checks):
            return 0
    return deliver_mod.deliver(cfg) if do_deliver else 0


def cmd_accept(cfg, args) -> int:
    seen = state.read_json(cfg.state_dir / "seen.json", {})
    fps = list(seen) if args.all_seen else args.fingerprints
    if not fps:
        print("nothing to accept")
        return 1
    crit = [fp for fp in fps if seen.get(fp, {}).get("severity") == "critical"]
    if args.all_seen or len(fps) > 5 or crit:
        print(f"Accept {len(fps)} findings ({len(crit)} critical) for {args.days} days? Type YES: ", end="", flush=True)
        if sys.stdin.readline().strip() != "YES":
            print("aborted")
            return 1
    n = baseline.accept(cfg.state_dir, fps, args.reason, args.days, state.now(cfg.timezone).date(), seen)
    print(f"accepted {n}")
    return 0


def cmd_status(cfg) -> int:
    files = sorted(state.Runs(cfg.state_dir).dir.glob("*.json"))
    if not files:
        print("no runs yet")
        return 1
    last = state.read_json(files[-1])
    print(json.dumps(last, ensure_ascii=False, indent=2))
    day = cfg.state_dir / "reports" / last["run_id"]
    s = state.read_json(day / "summary.json")
    if s:
        print(json.dumps(s, ensure_ascii=False, indent=2))
        print(day / "report.md")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="msec")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("nightly").add_argument("--force", action="store_true")
    sub.add_parser("deliver")
    a = sub.add_parser("accept")
    a.add_argument("fingerprints", nargs="*")
    a.add_argument("--all-seen", action="store_true")
    a.add_argument("--reason", required=True)
    a.add_argument("--days", type=int, default=90)
    sub.add_parser("status")
    sub.add_parser("install").add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    try:
        cfg = config.load()
    except (config.ConfigError, TypeError, ValueError, OSError) as e:
        print(f"msec: config error: {e}", file=sys.stderr)
        if args.cmd == "deliver":     # otherwise a broken config silences both jobs
            deliver_mod.notify_macos(CONFIG_TEXT)
        return 2
    if args.cmd == "nightly":
        return nightly(cfg, force=args.force)
    if args.cmd == "deliver":
        return deliver_mod.deliver(cfg)
    if args.cmd == "accept":
        return cmd_accept(cfg, args)
    if args.cmd == "status":
        return cmd_status(cfg)
    from . import install as install_mod
    entry = Path(__file__).resolve().parent.parent / "bin" / "msec"
    return install_mod.install(cfg, entry=entry, launch_agents=Path.home() / "Library/LaunchAgents",
                               uid=os.getuid(), dry_run=args.dry_run)

"""msec nightly | deliver | accept | status | install"""
import argparse
import json
import os
import sys
from pathlib import Path

from . import baseline, config, report, state, summary
from . import deliver as deliver_mod
from . import triage as triage_mod
from .checks import Ctx, agents, packages, persistence
from .findings import not_scanned

CHECKS = (persistence.run, agents.run, packages.run)


def collect(ctx, checks=CHECKS) -> list:
    results = []
    for fn in checks:
        try:
            results.extend(fn(ctx))
        except Exception as e:      # one broken check must not hide the others
            results.append(not_scanned(fn.__module__.rsplit(".", 1)[-1], f"check crashed: {type(e).__name__}: {e}"))
    return results


def nightly(cfg, force: bool = False, checks=CHECKS, do_deliver: bool = True) -> int:
    started = state.now(cfg.timezone)
    rid = state.run_id(started)
    runs = state.Runs(cfg.state_dir)
    if not runs.start(rid, started, force):
        print(f"run {rid} already complete")
        return 0
    try:
        state.ensure_dir(cfg.state_dir)
        sandbox = state.ensure_dir(cfg.state_dir / "sandbox")
        ctx = Ctx(home=Path.home(), scan_roots=cfg.scan_roots, sandbox=sandbox, uid=os.getuid())
        results = collect(ctx, checks)
        findings = list({f.fingerprint: f for r in results for f in r.findings}.values())  # dedupe, first wins
        seen = state.read_json(cfg.state_dir / "seen.json", {})
        accepted = (state.read_json(cfg.state_dir / "baseline.json", {}) or {}).get("accepted", {})
        if not isinstance(accepted, dict):
            accepted = {}
        today = started.date()
        new, open_items, acc, resolved = baseline.classify(findings, seen, accepted, today)
        open_crit = [f for f in open_items if f.severity == "critical"]
        tri, tri_err = triage_mod.triage(cfg.triage, new + open_crit, home=Path.home(), cwd=sandbox)
        day = state.ensure_dir(cfg.state_dir / "reports" / rid)
        state.write_json(day / "findings.json", [f.to_json() for f in findings])
        state.write_text(day / "report.md", report.render(rid, new, open_items, acc, resolved, results, tri, tri_err))
        state.write_json(day / "summary.json", summary.build(rid, new, open_crit, results))
        state.write_json(cfg.state_dir / "seen.json", baseline.update_seen(seen, findings, today))
        runs.finish(rid, state.now(cfg.timezone), "complete")
    except Exception as e:
        runs.finish(rid, state.now(cfg.timezone), "failed", f"{type(e).__name__}: {e}")
        raise
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

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from msec import baseline, cli, config, state, summary
from msec.config import Config, Triage
from msec.findings import Finding, not_scanned, result


def crit_check(ctx):
    return [result("fake", [Finding("fake", "persistence", "critical", "planted", {"id": 1})])]


def dup_check(ctx):
    f = Finding("fake", "persistence", "critical", "planted", {"id": 1})
    return [result("fake", [f, f])]


def crashing_check(ctx):
    raise RuntimeError("boom")


class CliTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.cfg = Config((self.dir,), "Europe/Lisbon", "08:30", Triage(enabled=False), ("macos-notify",), self.dir / "state")

    def rid(self):
        return state.run_id(state.now("Europe/Lisbon"))

    def summary(self):
        return state.read_json(self.cfg.state_dir / "reports" / self.rid() / "summary.json")

    def test_new_then_open_then_accepted(self):
        cli.nightly(self.cfg, checks=(crit_check,), do_deliver=False)
        self.assertEqual(self.summary()["counts"]["critical"], 1)
        cli.nightly(self.cfg, force=True, checks=(crit_check,), do_deliver=False)
        s = self.summary()
        self.assertEqual((s["counts"]["critical"], s["open_critical"]), (0, 1))
        seen = state.read_json(self.cfg.state_dir / "seen.json")
        baseline.accept(self.cfg.state_dir, list(seen), "test", 30, state.now("Europe/Lisbon").date(), seen)
        cli.nightly(self.cfg, force=True, checks=(crit_check,), do_deliver=False)
        self.assertEqual(self.summary()["open_critical"], 0)

    def report(self):
        return (self.cfg.state_dir / "reports" / self.rid() / "report.md").read_text()

    def test_second_run_same_day_is_skipped(self):
        cli.nightly(self.cfg, checks=(crit_check,), do_deliver=False)
        before = (self.cfg.state_dir / "seen.json").stat().st_mtime_ns
        with contextlib.redirect_stdout(io.StringIO()) as out:
            cli.nightly(self.cfg, checks=(crit_check,), do_deliver=False)
        self.assertEqual(before, (self.cfg.state_dir / "seen.json").stat().st_mtime_ns)
        self.assertIn("already complete", out.getvalue())

    def test_not_scanned_alerts_once_then_digest(self):
        gap = lambda ctx: [not_scanned("fake.tool", "tool not installed")]
        cli.nightly(self.cfg, checks=(gap,), do_deliver=False)
        s = self.summary()
        self.assertEqual((s["counts"]["medium"], s["categories"]), (1, ["coverage"]))
        self.assertIsNotNone(summary.message(s))
        cli.nightly(self.cfg, force=True, checks=(gap,), do_deliver=False)
        self.assertIsNone(summary.message(self.summary()))
        self.assertIn("## Відкриті, дайджест (1)", self.report())

    def test_failed_check_keeps_its_seen_items(self):
        x = Finding("fake.src", "persistence", "medium", "x", {"id": 1})
        mode = {"ok": True}
        check = lambda ctx: [result("fake.src", [x])] if mode["ok"] else [not_scanned("fake.src.partial", "timed out")]
        cli.nightly(self.cfg, checks=(check,), do_deliver=False)
        mode["ok"] = False
        cli.nightly(self.cfg, force=True, checks=(check,), do_deliver=False)
        self.assertIn(x.fingerprint, state.read_json(self.cfg.state_dir / "seen.json"))
        self.assertIn("Зникло з минулого разу: 0", self.report())
        mode["ok"] = True
        cli.nightly(self.cfg, force=True, checks=(check,), do_deliver=False)
        self.assertEqual(self.summary()["counts"]["medium"], 0)         # x is open, not new
        self.assertIn(f"`{x.fingerprint}` x", self.report())           # listed in the digest

    def test_missing_scan_root_is_coverage_finding(self):
        seen_roots = []
        probe = lambda ctx: seen_roots.append(ctx.scan_roots) or [result("fake", [])]
        gone = self.dir / "gone"
        cfg = Config((self.dir, gone), "Europe/Lisbon", "08:30", Triage(enabled=False), ("macos-notify",),
                     self.dir / "state")
        cli.nightly(cfg, checks=(probe,), do_deliver=False)
        self.assertEqual(seen_roots, [(self.dir,)])
        self.assertIn("config.scan_root", self.summary()["not_scanned"])
        fs = state.read_json(self.cfg.state_dir / "reports" / self.rid() / "findings.json")
        cov = [f for f in fs if f["check"] == "coverage"]
        self.assertEqual([(f["key"], f["severity"]) for f in cov], [({"check": "config.scan_root"}, "medium")])

    def test_triage_crash_does_not_fail_the_run(self):
        with mock.patch.object(cli.triage_mod, "triage", side_effect=RuntimeError("boom")):
            cli.nightly(self.cfg, checks=(crit_check,), do_deliver=False)
        self.assertEqual(state.Runs(self.cfg.state_dir).get(self.rid())["status"], "complete")
        self.assertIn("triage crashed: RuntimeError: boom", self.report())

    def test_nightly_lock_held_skips(self):
        with state.locked(self.cfg.state_dir / "nightly.lock") as got, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertTrue(got)
            self.assertEqual(cli.nightly(self.cfg, checks=(crit_check,), do_deliver=False), 0)
        self.assertEqual(out.getvalue().strip(), "nightly already running")
        self.assertIsNone(state.Runs(self.cfg.state_dir).get(self.rid()))
        self.assertEqual((self.cfg.state_dir / "nightly.lock").stat().st_mode & 0o777, 0o600)

    def test_crashing_check_does_not_hide_others(self):
        cli.nightly(self.cfg, checks=(crashing_check, crit_check), do_deliver=False)
        s = self.summary()
        self.assertEqual(s["counts"]["critical"], 1)
        self.assertEqual(s["not_scanned"], ["test_cli"])

    def test_large_first_run_counts_everything(self):
        many = lambda ctx: [result("bulk", [Finding("bulk", "agent-config", "medium", f"item {i}", {"i": i}) for i in range(300)])]
        cli.nightly(self.cfg, checks=(many,), do_deliver=False)
        self.assertEqual(self.summary()["counts"]["medium"], 300)
        self.assertIn("## Нове (300)", (self.cfg.state_dir / "reports" / self.rid() / "report.md").read_text())

    def test_report_and_findings_written(self):
        cli.nightly(self.cfg, checks=(crit_check,), do_deliver=False)
        d = self.cfg.state_dir / "reports" / self.rid()
        self.assertIn("planted", (d / "report.md").read_text())
        self.assertEqual(len(state.read_json(d / "findings.json")), 1)
        self.assertEqual(state.Runs(self.cfg.state_dir).get(self.rid())["status"], "complete")

    def test_duplicate_findings_deduped(self):
        cli.nightly(self.cfg, checks=(dup_check,), do_deliver=False)
        self.assertEqual(self.summary()["counts"]["critical"], 1)
        d = self.cfg.state_dir / "reports" / self.rid()
        self.assertEqual(len(state.read_json(d / "findings.json")), 1)

    def test_baseline_without_accepted_key(self):
        state.write_json(self.cfg.state_dir / "baseline.json", {})
        cli.nightly(self.cfg, checks=(crit_check,), do_deliver=False)
        self.assertEqual(self.summary()["counts"]["critical"], 1)
        seen = state.read_json(self.cfg.state_dir / "seen.json")
        baseline.accept(self.cfg.state_dir, list(seen), "t", 5, state.now("Europe/Lisbon").date(), seen)
        self.assertEqual(len(state.read_json(self.cfg.state_dir / "baseline.json")["accepted"]), 1)

    def test_config_error_returns_2(self):
        with mock.patch.object(cli.config, "load", side_effect=config.ConfigError("bad")), \
                mock.patch.object(cli.deliver_mod, "notify_macos") as notify, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["status"]), 2)
        notify.assert_not_called()

    def test_config_error_in_deliver_notifies(self):
        with mock.patch.object(cli.config, "load", side_effect=config.ConfigError("bad")), \
                mock.patch.object(cli.deliver_mod, "notify_macos", return_value=True) as notify, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["deliver"]), 2)
        notify.assert_called_once_with("⚠ msec: конфіг не читається — msec status")


if __name__ == "__main__":
    unittest.main()

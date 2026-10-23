import tempfile
import unittest
from pathlib import Path
from unittest import mock

from msec import baseline, cli, config, state
from msec.config import Config, Triage
from msec.findings import Finding, result


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

    def test_second_run_same_day_is_skipped(self):
        cli.nightly(self.cfg, checks=(crit_check,), do_deliver=False)
        before = (self.cfg.state_dir / "seen.json").stat().st_mtime_ns
        cli.nightly(self.cfg, checks=(crit_check,), do_deliver=False)
        self.assertEqual(before, (self.cfg.state_dir / "seen.json").stat().st_mtime_ns)

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
        with mock.patch.object(cli.config, "load", side_effect=config.ConfigError("bad")):
            self.assertEqual(cli.main(["status"]), 2)


if __name__ == "__main__":
    unittest.main()

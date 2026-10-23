import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from msec import cli, config
from msec.config import Triage
from msec.findings import Finding, result


def crit_check(ctx):
    return [result("fake", [Finding("fake", "persistence", "critical", "planted", {"id": 1}),
                            Finding("fake", "persistence", "critical", "planted", {"id": 1})])]   # duplicate


def roots_check(ctx):
    return [result("roots", [Finding("roots", "agent-config", "medium", f"root {r.name}", {"r": str(r)})
                             for r in ctx.scan_roots])]


class ScanTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.cache = self.tmp / "cache"
        self.root = self.tmp / "repos"
        self.root.mkdir()

    def run_scan(self, **kw):
        kw.setdefault("cache", self.cache)
        buf = io.StringIO()
        with redirect_stdout(buf):
            out = cli.scan(**kw)
        return out, buf.getvalue()

    def test_writes_report_everything_new_and_prints_path(self):
        out, printed = self.run_scan(roots=(self.root,), checks=(crit_check,))
        s = json.loads((out / "summary.json").read_text())
        self.assertEqual(s["counts"]["critical"], 1)            # deduped
        self.assertEqual(len(json.loads((out / "findings.json").read_text())), 1)
        md = (out / "report.md").read_text()
        self.assertIn("planted", md)
        self.assertNotIn("msec accept", md)                     # no baseline in a one-off scan
        self.assertIn(str(out / "report.md"), printed)
        self.assertIn("🔴1", printed)

    def test_does_not_touch_msec_state_or_notify(self):
        state_dir = self.tmp / "state"
        with mock.patch.object(cli.deliver_mod, "notify_macos", side_effect=AssertionError("notified")), \
             mock.patch.object(cli.state, "Runs", side_effect=AssertionError("run state touched")):
            out, _ = self.run_scan(roots=(self.root,), checks=(crit_check,))
        self.assertFalse(state_dir.exists())
        self.assertEqual(sorted(p.name for p in out.iterdir()), ["findings.json", "report.md", "summary.json"])

    def test_no_triage_unless_asked(self):
        with mock.patch.object(cli.triage_mod, "triage", side_effect=AssertionError("triage ran")):
            self.run_scan(roots=(self.root,), checks=(crit_check,))
        with mock.patch.object(cli.triage_mod, "triage", return_value=(None, "claude binary not found")) as t:
            out, _ = self.run_scan(roots=(self.root,), checks=(crit_check,), tri_cfg=Triage(claude_path="/x/claude"))
        self.assertEqual(t.call_count, 1)
        self.assertIn("claude binary not found", (out / "report.md").read_text())

    def test_missing_and_absent_roots_are_reported(self):
        out, _ = self.run_scan(roots=(), checks=(roots_check,))
        self.assertIn("scan.roots", json.loads((out / "summary.json").read_text())["not_scanned"])
        out, _ = self.run_scan(roots=(self.tmp / "nope",), checks=(roots_check,))
        self.assertIn("config.scan_root", json.loads((out / "summary.json").read_text())["not_scanned"])

    def test_out_dir_is_a_fresh_private_subdir(self):
        parent = self.tmp / "desk"
        parent.mkdir(mode=0o755)
        out, _ = self.run_scan(roots=(self.root,), checks=(crit_check,), out_parent=parent)
        self.assertEqual(out.parent, parent)
        self.assertEqual(parent.stat().st_mode & 0o777, 0o755)  # caller's folder untouched
        self.assertEqual(out.stat().st_mode & 0o777, 0o700)

    def test_main_scan_works_without_config(self):
        with mock.patch.object(cli.config, "load", side_effect=config.ConfigError("no config")), \
             mock.patch.object(cli, "CHECKS", (roots_check,)), \
             mock.patch.object(cli, "SCAN_CACHE", self.cache), \
             redirect_stdout(io.StringIO()) as buf:
            rc = cli.main(["scan", "--root", str(self.root), "--out", str(self.tmp)])
        self.assertEqual(rc, 0)
        self.assertIn("report.md", buf.getvalue())


if __name__ == "__main__":
    unittest.main()

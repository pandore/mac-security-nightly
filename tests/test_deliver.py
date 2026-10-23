import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from msec import config, deliver, state, summary
from msec.config import Config, Triage
from msec.findings import Finding

TZ = ZoneInfo("Europe/Lisbon")


def at(h, m):
    return datetime(2026, 10, 24, h, m, tzinfo=TZ)


class DecideTest(unittest.TestCase):
    def test_matrix(self):
        complete = {"status": "complete"}
        cases = [
            (complete, at(8, 0), "wait"),
            (complete, at(8, 31), "send"),
            ({**complete, "delivered_at": "x"}, at(9, 0), "done"),
            (None, at(8, 40), "wait"),              # Mac just woke; nightly catch-up not started yet
            (None, at(10, 31), "missing"),
            ({"status": "failed"}, at(8, 31), "missing"),
            ({"status": "failed", "alerted_missing_at": "x"}, at(11, 0), "done"),
            ({"status": "running", "started_at": at(8, 20).isoformat()}, at(8, 31), "wait"),
            ({"status": "running", "started_at": at(4, 0).isoformat()}, at(8, 31), "missing"),
        ]
        for rs, now, want in cases:
            with self.subTest(rs=rs, now=now):
                self.assertEqual(deliver.decide(rs, now, "08:30"), want)

    def test_adapter_names_match_config(self):
        self.assertEqual(set(deliver.ADAPTERS), set(config.ADAPTERS))


class DeliverTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.cfg = Config((self.dir,), "Europe/Lisbon", "08:30", Triage(enabled=False), ("macos-notify",), self.dir)
        self.sent = []
        self.adapters = {"macos-notify": lambda text: self.sent.append(text) or True}

    def complete_run(self, new):
        runs = state.Runs(self.dir)
        runs.start("2026-10-24", at(4, 0))
        state.write_json(self.dir / "reports/2026-10-24/summary.json", summary.build("2026-10-24", new, [], []))
        runs.finish("2026-10-24", at(4, 10), "complete")
        return runs

    def test_sends_once(self):
        runs = self.complete_run([Finding("c", "ioc", "critical", "t", {})])
        self.assertEqual(deliver.deliver(self.cfg, now=at(8, 31), adapters=self.adapters), 0)
        deliver.deliver(self.cfg, now=at(11, 0), adapters=self.adapters)
        self.assertEqual(len(self.sent), 1)
        self.assertIn("🔴1", self.sent[0])
        self.assertIn("delivered_at", runs.get("2026-10-24"))

    def test_quiet_run_sends_nothing_but_marks_delivered(self):
        runs = self.complete_run([])
        deliver.deliver(self.cfg, now=at(8, 31), adapters=self.adapters)
        self.assertEqual(self.sent, [])
        self.assertIn("delivered_at", runs.get("2026-10-24"))

    def test_missing_run_alerts_once_after_grace(self):
        deliver.deliver(self.cfg, now=at(8, 31), adapters=self.adapters)
        self.assertEqual(self.sent, [])
        deliver.deliver(self.cfg, now=at(11, 0), adapters=self.adapters)
        deliver.deliver(self.cfg, now=at(11, 5), adapters=self.adapters)
        self.assertEqual(self.sent, [deliver.MISSING_TEXT])

    def test_adapter_failure_is_retried_next_trigger(self):
        self.complete_run([Finding("c", "ioc", "critical", "t", {})])
        failing = {"macos-notify": lambda text: False}
        self.assertEqual(deliver.deliver(self.cfg, now=at(8, 31), adapters=failing), 1)
        deliver.deliver(self.cfg, now=at(11, 0), adapters=self.adapters)
        self.assertEqual(len(self.sent), 1)

    def test_tampered_summary_is_not_sent(self):
        runs = state.Runs(self.dir)
        runs.start("2026-10-24", at(4, 0))
        state.write_json(self.dir / "reports/2026-10-24/summary.json",
                         {"run_id": "2026-10-24", "counts": {"critical": "rm -rf"}, "open_critical": 0, "categories": []})
        runs.finish("2026-10-24", at(4, 10), "complete")
        deliver.deliver(self.cfg, now=at(8, 31), adapters=self.adapters)
        self.assertEqual(self.sent, [deliver.MISSING_TEXT])

    def test_list_summary_sends_missing_text_not_exception(self):
        runs = state.Runs(self.dir)
        runs.start("2026-10-24", at(4, 0))
        state.write_json(self.dir / "reports/2026-10-24/summary.json", [{"counts": 1}])
        runs.finish("2026-10-24", at(4, 10), "complete")
        self.assertEqual(deliver.deliver(self.cfg, now=at(8, 31), adapters=self.adapters), 0)
        self.assertEqual(self.sent, [deliver.MISSING_TEXT])


if __name__ == "__main__":
    unittest.main()

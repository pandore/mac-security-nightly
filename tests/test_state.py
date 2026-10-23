import os
import stat
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from msec import state

TZ = ZoneInfo("Europe/Lisbon")


class StateTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp()) / "state"

    def test_atomic_write_and_permissions(self):
        p = self.dir / "a" / "b.json"
        state.write_json(p, {"x": 1})
        self.assertEqual(state.read_json(p), {"x": 1})
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(p.parent.stat().st_mode), 0o700)
        self.assertEqual([x.name for x in p.parent.iterdir()], ["b.json"])   # no temp leftovers

    def test_refuses_to_write_through_symlink(self):
        target = self.dir.parent / "outside.txt"
        target.write_text("keep")
        self.dir.mkdir(parents=True)
        os.symlink(target, self.dir / "link.txt")
        with self.assertRaises(RuntimeError):
            state.write_text(self.dir / "link.txt", "pwned")
        self.assertEqual(target.read_text(), "keep")

    def test_read_missing_returns_default(self):
        self.assertEqual(state.read_json(self.dir / "nope.json", {}), {})

    def test_runs_creates_private_state_root(self):
        fresh = self.dir / "fresh"
        state.Runs(fresh)
        self.assertEqual(stat.S_IMODE(fresh.stat().st_mode), 0o700)

    def test_run_id_is_local_date(self):
        at = datetime(2026, 10, 24, 0, 30, tzinfo=TZ)
        self.assertEqual(state.run_id(at), "2026-10-24")

    def test_runs_lifecycle(self):
        runs = state.Runs(self.dir)
        at = datetime(2026, 10, 24, 4, 0, tzinfo=TZ)
        self.assertTrue(runs.start("2026-10-24", at))
        self.assertEqual(runs.get("2026-10-24")["status"], "running")
        runs.finish("2026-10-24", at + timedelta(minutes=10), "complete")
        self.assertFalse(runs.start("2026-10-24", at))            # already complete: skip
        self.assertTrue(runs.start("2026-10-24", at, force=True))
        runs.finish("2026-10-24", at, "failed", "boom" * 500)
        self.assertLessEqual(len(runs.get("2026-10-24")["error"]), 500)
        runs.mark("2026-10-24", "delivered_at", at)
        self.assertIn("delivered_at", runs.get("2026-10-24"))


if __name__ == "__main__":
    unittest.main()

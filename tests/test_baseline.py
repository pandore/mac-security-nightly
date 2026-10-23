import json
import stat
import tempfile
import unittest
from datetime import date
from pathlib import Path

from msec import baseline, state
from msec.findings import Finding

TODAY = date(2026, 10, 24)


def f(n, sev="high"):
    return Finding("c", "persistence", sev, f"item {n}", {"n": n})


class BaselineTest(unittest.TestCase):
    def test_classify_new_open_accepted_resolved(self):
        a, b, c, d = f(1), f(2), f(3), f(4)
        seen = {b.fingerprint: {}, c.fingerprint: {}, "gone0000gone0000": {}}
        accepted = {c.fingerprint: {"until": "2026-12-01"}}
        new, open_items, acc, resolved = baseline.classify([a, b, c], seen, accepted, TODAY)
        self.assertEqual(new, [a])
        self.assertEqual(open_items, [b])
        self.assertEqual(acc, [c])
        self.assertEqual(resolved, ["gone0000gone0000"])
        self.assertNotIn(d, new)

    def test_expired_acceptance_is_new_again(self):
        x = f(1, "critical")
        seen = {x.fingerprint: {}}
        new, open_items, acc, _ = baseline.classify([x], seen, {x.fingerprint: {"until": "2026-10-23"}}, TODAY)
        self.assertEqual((new, open_items, acc), ([x], [], []))

    def test_critical_stays_open_until_accepted(self):
        x = f(1, "critical")
        new, open_items, _, _ = baseline.classify([x], {x.fingerprint: {}}, {}, TODAY)
        self.assertEqual((new, open_items), ([], [x]))

    def test_update_seen_keeps_first_seen_and_drops_resolved(self):
        a, b = f(1), f(2)
        seen = {a.fingerprint: {"first_seen": "2026-10-01"}, "old": {"first_seen": "2026-09-01"}}
        out = baseline.update_seen(seen, [a, b], TODAY)
        self.assertEqual(out[a.fingerprint]["first_seen"], "2026-10-01")
        self.assertEqual(out[b.fingerprint]["first_seen"], "2026-10-24")
        self.assertNotIn("old", out)

    def test_accept_writes_baseline_and_log(self):
        d = Path(tempfile.mkdtemp())
        a = f(1)
        known = {a.fingerprint: {"title": a.title, "severity": a.severity}}
        n = baseline.accept(d, [a.fingerprint], "my dev server", 90, TODAY, known)
        self.assertEqual(n, 1)
        acc = state.read_json(d / "baseline.json")["accepted"][a.fingerprint]
        self.assertEqual(acc["until"], "2027-01-22")
        log = (d / "accept.log").read_text().splitlines()
        self.assertEqual(json.loads(log[0])["fingerprint"], a.fingerprint)
        self.assertEqual(stat.S_IMODE((d / "accept.log").stat().st_mode), 0o600)

    def test_accept_validation(self):
        d = Path(tempfile.mkdtemp())
        a = f(1)
        known = {a.fingerprint: {"title": "t", "severity": "high"}}
        for fps, reason, days in [(["0123456789abcdef"], "r", 30), ([a.fingerprint], " ", 30),
                                  ([a.fingerprint], "r", 0), ([a.fingerprint], "r", 400)]:
            with self.subTest(fps=fps, reason=reason, days=days), self.assertRaises(ValueError):
                baseline.accept(d, fps, reason, days, TODAY, known)


if __name__ == "__main__":
    unittest.main()

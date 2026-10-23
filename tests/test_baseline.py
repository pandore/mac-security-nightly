import json
import os
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

    def test_expired_acceptance_is_new_only_once(self):
        x = f(1, "medium")
        acc = {x.fingerprint: {"until": "2026-10-24"}}
        seen = {x.fingerprint: {"first_seen": "2026-10-01", "last_seen": "2026-10-24"}}
        d1, d2 = date(2026, 10, 25), date(2026, 10, 26)
        new, open_items, _, _ = baseline.classify([x], seen, acc, d1)
        self.assertEqual((new, open_items), ([x], []))
        seen = baseline.update_seen(seen, [x], d1)
        new, open_items, _, _ = baseline.classify([x], seen, acc, d2)
        self.assertEqual((new, open_items), ([], [x]))

    def test_accepted_info_that_turns_critical_is_new(self):
        key = {"source": "/r/p/package-lock.json", "package": "npm/foo", "version": "1.0.0"}
        info = Finding("packages.osv", "packages", "info", "foo: 2 advisories", key)
        mal = Finding("packages.osv", "ioc", "critical", "foo: MALICIOUS MAL-1", key)
        seen = {info.fingerprint: {"last_seen": "2026-10-23"}}
        new, _, acc, _ = baseline.classify([mal], seen, {info.fingerprint: {"until": "2027-01-01"}}, TODAY)
        self.assertEqual((new, acc), ([mal], []))

    def test_update_seen_carries_items_of_skipped_checks(self):
        seen = {"osv0": {"source": "packages.osv", "last_seen": "2026-10-23"},
                "brew": {"source": "packages.brew"}, "repo": {"source": "agents.repo", "last_seen": "2026-10-23"}, "old": {}}
        a = f(1)
        out = baseline.update_seen(seen, [a], TODAY, {a.fingerprint: "c"}, ["packages.osv.partial", "agents"])
        self.assertEqual(out["osv0"], seen["osv0"])          # partial scan: kept untouched
        self.assertIn("repo", out)                            # whole module crashed: kept
        self.assertNotIn("brew", out)
        self.assertNotIn("old", out)
        self.assertEqual(out[a.fingerprint]["source"], "c")

    def test_partial_covers_only_its_own_source_and_only_for_three_days(self):
        x = f(1)
        sk = ["agents.partial"]
        seen = {x.fingerprint: {"source": "agents", "last_seen": "2026-10-20"},
                "sub": {"source": "agents.repo", "last_seen": "2026-10-23"}}
        out = baseline.update_seen(seen, [], date(2026, 10, 23), None, sk)    # night 2: absent, in window
        self.assertIn(x.fingerprint, out)
        self.assertNotIn("sub", out)                                          # .partial does not cover agents.*
        out = baseline.update_seen(out, [], date(2026, 10, 24), None, sk)     # 4 days since last_seen
        self.assertNotIn(x.fingerprint, out)
        new, _, _, _ = baseline.classify([x], out, {}, date(2026, 10, 29))    # re-added later: new
        self.assertEqual(new, [x])

    def test_launchd_item_removed_under_partial_resolves_after_window(self):
        seen = {"p": {"source": "persistence.launchd", "last_seen": "2026-10-20"}}
        sk = ["persistence.launchd.partial"]
        self.assertIn("p", baseline.update_seen(seen, [], date(2026, 10, 23), None, sk))
        self.assertNotIn("p", baseline.update_seen(seen, [], date(2026, 10, 24), None, sk))

    def test_fully_skipped_check_recovering_keeps_items_open(self):
        x = f(1)
        seen = {x.fingerprint: {"source": "c", "last_seen": "2026-10-22"}}
        for d in (23, 24):                         # two nights not scanned
            seen = baseline.update_seen(seen, [], date(2026, 10, d), None, ["c"])
        self.assertIn(x.fingerprint, seen)
        new, open_items, _, _ = baseline.classify([x], seen, {}, date(2026, 10, 25))
        self.assertEqual((new, open_items), ([], [x]))

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

    def test_accept_creates_missing_state_dir(self):
        d = Path(tempfile.mkdtemp()) / "missing" / "state"
        a = f(1)
        known = {a.fingerprint: {"title": a.title, "severity": "high"}}
        self.assertEqual(baseline.accept(d, [a.fingerprint], "r", 30, TODAY, known), 1)
        self.assertTrue((d / "baseline.json").is_file())
        self.assertTrue((d / "accept.log").is_file())

    def test_failed_baseline_write_leaves_no_log(self):
        d = Path(tempfile.mkdtemp())
        a = f(1)
        known = {a.fingerprint: {"title": a.title, "severity": "high"}}
        target = d / "elsewhere.json"  # absent: read falls back to the empty default
        os.symlink(target, d / "baseline.json")
        with self.assertRaises(RuntimeError):
            baseline.accept(d, [a.fingerprint], "r", 30, TODAY, known)
        self.assertFalse((d / "accept.log").exists())


if __name__ == "__main__":
    unittest.main()

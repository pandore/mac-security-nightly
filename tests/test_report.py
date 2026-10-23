import unittest

from msec import report
from msec.findings import Finding, not_scanned, result


class ReportTest(unittest.TestCase):
    def test_sections_and_model_labels(self):
        crit = Finding("persistence.launchd", "persistence", "critical", "evil `agent`|x", {"n": 1}, fix=("launchctl bootout gui/501 '/p'",))
        info = Finding("updates.npm", "updates", "info", "npm x", {"n": 2})
        tri = {"overview": "Спершу глянь на агент.", "items": {crit.fingerprint: {"explanation": "Схоже на стілер.", "likely_benign": False}}}
        md = report.render("2026-10-24", [crit], [info], [], ["dead"], [result("c", [crit]), not_scanned("x", "no FDA")], tri, "")
        self.assertIn("# Mac security — 2026-10-24", md)
        self.assertIn("Огляд (пояснення моделі", md)
        self.assertIn("Модель: Схоже на стілер.", md)
        self.assertIn("Виправлення: `launchctl bootout gui/501 '/p'`", md)
        self.assertIn("evil 'agent'/x", md)          # backticks and pipes neutralised in titles
        self.assertIn("- x: no FDA", md)
        self.assertIn("Зникло з минулого разу: 1", md)

    def test_triage_error_is_visible(self):
        md = report.render("2026-10-24", [], [], [], [], [], None, "triage timed out")
        self.assertIn("Аналіз моделлю не виконано: triage timed out", md)

    def test_info_only_as_counts(self):
        infos = [Finding("packages.osv", "packages", "info", f"pkg{i}", {"i": i}) for i in range(3)]
        infos.append(Finding("updates.npm", "updates", "info", "npmthing", {"n": 1}))
        md = report.render("2026-10-24", infos[:2], infos[2:], [], [], [], None, "")
        self.assertNotIn("### ⚪", md)
        self.assertNotIn("pkg0", md)
        self.assertNotIn("npmthing", md)
        self.assertIn("- ⚪ info: 2 × packages.osv", md)
        self.assertIn("- ⚪ info: 1 × packages.osv, 1 × updates.npm", md)


if __name__ == "__main__":
    unittest.main()

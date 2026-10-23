import unittest

from msec.findings import CheckResult, Finding, clean, not_scanned, result


class FindingTest(unittest.TestCase):
    def test_fingerprint_is_stable_and_ignores_title_and_severity(self):
        a = Finding("persistence.launchd", "persistence", "critical", "A", {"plist": "/x", "program": "/bin/sh"})
        b = Finding("persistence.launchd", "persistence", "medium", "B", {"program": "/bin/sh", "plist": "/x"})
        self.assertEqual(a.fingerprint, b.fingerprint)
        self.assertRegex(a.fingerprint, r"^[0-9a-f]{16}$")

    def test_fingerprint_changes_with_key(self):
        a = Finding("c", "ioc", "critical", "t", {"path": "/a"})
        b = Finding("c", "ioc", "critical", "t", {"path": "/b"})
        self.assertNotEqual(a.fingerprint, b.fingerprint)

    def test_bad_enums_rejected(self):
        with self.assertRaises(ValueError):
            Finding("c", "ioc", "urgent", "t", {})
        with self.assertRaises(ValueError):
            Finding("c", "everything", "info", "t", {})
        with self.assertRaises(ValueError):
            CheckResult("c", "maybe")

    def test_title_is_cleaned(self):
        f = Finding("c", "ioc", "info", "line1\nline2\x1b[31m" + "x" * 500, {})
        self.assertNotIn("\n", f.title)
        self.assertNotIn("\x1b", f.title)
        self.assertLessEqual(len(f.title), 200)

    def test_clean_collapses_whitespace(self):
        self.assertEqual(clean("  a \t\n b  "), "a b")

    def test_result_helpers(self):
        self.assertEqual(result("c", []).status, "ok")
        self.assertEqual(result("c", [Finding("c", "ioc", "info", "t", {})]).status, "findings")
        ns = not_scanned("c", "no FDA\n")
        self.assertEqual((ns.status, ns.reason), ("not_scanned", "no FDA"))

    def test_to_json_has_fingerprint(self):
        f = Finding("c", "ioc", "info", "t", {"k": 1}, fix=("brew upgrade x",))
        j = f.to_json()
        self.assertEqual(j["fingerprint"], f.fingerprint)
        self.assertEqual(j["fix"], ["brew upgrade x"])


if __name__ == "__main__":
    unittest.main()

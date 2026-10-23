import unittest

from msec.findings import CheckResult, Finding, clean, not_scanned, result


class FindingTest(unittest.TestCase):
    def test_fingerprint_is_stable_and_ignores_title(self):
        a = Finding("persistence.launchd", "persistence", "critical", "A", {"plist": "/x", "program": "/bin/sh"})
        b = Finding("persistence.launchd", "persistence", "critical", "B", {"program": "/bin/sh", "plist": "/x"})
        self.assertEqual(a.fingerprint, b.fingerprint)
        self.assertRegex(a.fingerprint, r"^[0-9a-f]{16}$")

    def test_fingerprint_changes_with_severity(self):
        key = {"source": "/r/p/package-lock.json", "package": "npm/foo", "version": "1.0.0"}
        info = Finding("packages.osv", "packages", "info", "foo: 2 advisories", key)
        mal = Finding("packages.osv", "ioc", "critical", "foo: MALICIOUS MAL-1", key)
        self.assertNotEqual(info.fingerprint, mal.fingerprint)

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

    def test_clean_masks_secrets(self):
        cases = {
            "MCP server tav (claude, user): https://me:pw@mcp.tavily.com/mcp/?tavilyApiKey=tvly-abc123def456#frag":
                ("tvly-abc123def456", "me:pw", "pw@", "tavilyApiKey", "frag"),
            "Claude allow rule Bash(GITHUB_TOKEN=ghp_" + "a1" * 18 + " gh api:*)": ("a1a1a1a1",),
            "Claude hook Stop: Bash(curl -H 'Authorization: Bearer sk-ant-api03-xxxxxxxxQQ')": ("xxxxxxxxQQ",),
            "crontab entry: */5 * * * * API_KEY=Zq81mXk20vLp93nRt47w /bin/sync": ("Zq81mXk20vLp93nRt47w",),
            "AKIAIOSFODNN7EXAMPLE and AIzaSyA-1234567 and glpat-abcdefgh xoxb-12345678": ("IOSFODNN", "SyA-123", "abcdefgh", "12345678"),
        }
        for text, secrets in cases.items():
            with self.subTest(text=text):
                out = clean(text)
                for secret in secrets:
                    self.assertNotIn(secret, out)
        self.assertIn("https://mcp.tavily.com/mcp/?…", clean("x https://me:pw@mcp.tavily.com/mcp/?k=v y"))
        self.assertIn("ghp_…", clean("ghp_" + "a1" * 18))

    def test_clean_keeps_ordinary_text(self):
        for text in ("0123456789abcdef", "/Users/u/Repos/app/.claude/settings.json", "mac-security-nightly-tool",
                     "ffmpeg 9.0.2: CVE-2026-12345 HIGH — bad", "launchd com.task-runner.agent → /opt/x [ABCDE12345]",
                     "https://example.com/mcp"):
            with self.subTest(text=text):
                self.assertEqual(clean(text), text)

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

import os
import tempfile
import unittest
from pathlib import Path

from msec import runner


class RunnerTest(unittest.TestCase):
    def setUp(self):
        self.sandbox = Path(tempfile.mkdtemp()) / "sandbox"

    def test_env_does_not_inherit_secrets(self):
        os.environ["GITHUB_TOKEN"] = "ghp_should_not_leak"
        try:
            env = runner.scanner_env(self.sandbox)
            r = runner.run(["/usr/bin/env"], env=env, timeout=10)
        finally:
            del os.environ["GITHUB_TOKEN"]
        self.assertTrue(r.ok)
        self.assertNotIn("ghp_should_not_leak", r.stdout)
        self.assertIn(f"HOME={self.sandbox}", r.stdout)
        self.assertTrue((self.sandbox / "tmp").is_dir())

    def test_no_shell_interpretation(self):
        r = runner.run(["/bin/echo", "$(id)", ";", "|"], env=runner.scanner_env(self.sandbox), timeout=10)
        self.assertEqual(r.stdout.strip(), "$(id) ; |")

    def test_timeout(self):
        r = runner.run(["/bin/sleep", "5"], env=runner.scanner_env(self.sandbox), timeout=0.5)
        self.assertTrue(r.timed_out)
        self.assertIsNone(r.rc)
        self.assertFalse(r.ok)

    def test_missing_binary(self):
        r = runner.run(["/nonexistent/tool"], env=runner.scanner_env(self.sandbox), timeout=5)
        self.assertTrue(r.missing)
        self.assertFalse(r.ok)

    def test_stdin_is_passed(self):
        r = runner.run(["/bin/cat"], env=runner.scanner_env(self.sandbox), timeout=5, stdin_text="data")
        self.assertEqual(r.stdout, "data")


if __name__ == "__main__":
    unittest.main()

import io
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from msec import runner
from msec.checks import log_cmd


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

    def test_timeout_kills_grandchildren(self):
        t = time.monotonic()
        r = runner.run(["/bin/sh", "-c", "sleep 30 & sleep 30"], env=runner.scanner_env(self.sandbox), timeout=0.5)
        self.assertTrue(r.timed_out)
        self.assertLess(time.monotonic() - t, 5)

    def test_timeout_group_kill_reaps_grandchild(self):
        pidfile = self.sandbox.parent / "pid"
        runner.run(["/bin/sh", "-c", f"sleep 30 & echo $! > {pidfile}; sleep 30"],
                   env=runner.scanner_env(self.sandbox), timeout=0.5)
        pid = int(pidfile.read_text())
        time.sleep(0.2)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_undecodable_output_does_not_raise(self):
        r = runner.run(["/usr/bin/printf", "\\377\\376"], env=runner.scanner_env(self.sandbox), timeout=5)
        self.assertEqual(r.rc, 0)

    def test_non_executable_is_missing(self):
        f = self.sandbox.parent / "noexec"
        f.write_text("x")
        r = runner.run([str(f)], env=runner.scanner_env(self.sandbox), timeout=5)
        self.assertTrue(r.missing)

    def test_missing_binary(self):
        r = runner.run(["/nonexistent/tool"], env=runner.scanner_env(self.sandbox), timeout=5)
        self.assertTrue(r.missing)
        self.assertFalse(r.ok)

    def test_stdin_is_passed(self):
        r = runner.run(["/bin/cat"], env=runner.scanner_env(self.sandbox), timeout=5, stdin_text="data")
        self.assertEqual(r.stdout, "data")


class LogCmdTest(unittest.TestCase):
    def logged(self, r, secs):
        with mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            log_cmd(r, secs)
        return err.getvalue()

    def test_logs_slow_or_failed_commands_masked(self):
        quick = runner.CmdResult(("/usr/bin/codesign", "--verify"), 1, "", "not signed")
        self.assertEqual(self.logged(quick, 0.1), "")                    # rc 1 is a normal answer
        slow = runner.CmdResult(("/opt/homebrew/bin/osv-scanner", "scan"), 0, "", "query failed token=sk-abcdef1234567890")
        line = self.logged(slow, 61)
        self.assertIn("msec: osv-scanner scan: rc=0, 61s, stdout 0 B", line)
        self.assertNotIn("sk-abcdef1234567890", line)
        hung = runner.CmdResult(("/usr/bin/sfltool", "dumpbtm"), None, "", "", timed_out=True)
        self.assertIn("sfltool dumpbtm: timed out", self.logged(hung, 300))


if __name__ == "__main__":
    unittest.main()

import contextlib
import io
import os
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from msec import install
from msec.config import Config, Triage
from msec.runner import CmdResult


class InstallTest(unittest.TestCase):
    def test_plist_shape(self):
        p = install.plist_for("com.msec.nightly", Path("/opt/homebrew/bin/python3"), Path("/r/bin/msec"),
                              ["nightly"], [(4, 0)], Path("/s/logs"))
        self.assertEqual(p["ProgramArguments"], ["/opt/homebrew/bin/python3", "-I", "/r/bin/msec", "nightly"])
        self.assertEqual(p["StartCalendarInterval"], [{"Hour": 4, "Minute": 0}])
        self.assertEqual(p["StandardErrorPath"], "/s/logs/com.msec.nightly.log")
        plistlib.dumps(p)   # serialisable

    def test_rejects_relative_paths(self):
        with self.assertRaises(ValueError):
            install.plist_for("com.msec.nightly", Path("python3"), Path("/r/bin/msec"), ["nightly"], [(4, 0)], Path("/s"))

    def test_delivery_times(self):
        self.assertEqual(install.delivery_times("08:30"), [(8, 30), (11, 0)])
        self.assertEqual(install.delivery_times("22:45"), [(22, 45), (23, 59)])

    def test_dry_run_writes_nothing(self):
        d = Path(tempfile.mkdtemp())
        cfg = Config((d,), "Europe/Lisbon", "08:30", Triage(enabled=False), ("macos-notify",), d / "state")
        with contextlib.redirect_stdout(io.StringIO()):
            rc = install.install(cfg, entry=d / "bin/msec", launch_agents=d / "LA", uid=501, dry_run=True)
        self.assertEqual(rc, 0)
        self.assertFalse((d / "LA").exists())


def _cfg(d: Path) -> Config:
    return Config((d,), "Europe/Lisbon", "08:30", Triage(enabled=False), ("macos-notify",), d / "state")


def _ok(argv, **kw):
    return CmdResult(tuple(argv), 0, "", "")


def _fail(argv, **kw):
    return CmdResult(tuple(argv), 1, "", "boom")


class InstallWriteTest(unittest.TestCase):
    def test_writes_plists_0644_and_keeps_dir_mode(self):
        d = Path(tempfile.mkdtemp())
        la = d / "LA"
        la.mkdir()
        os.chmod(la, 0o755)
        with mock.patch("msec.install.run", side_effect=_ok), mock.patch("msec.install.time.sleep"), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(install.install(_cfg(d), entry=d / "bin/msec", launch_agents=la, uid=501), 0)
        for label in install.LABELS:
            p = la / f"{label}.plist"
            self.assertTrue(p.is_file())
            self.assertEqual(p.stat().st_mode & 0o777, 0o644)
        self.assertEqual(la.stat().st_mode & 0o777, 0o755)

    def test_symlinked_launchagents_refused(self):
        d = Path(tempfile.mkdtemp())
        real = d / "real"
        real.mkdir()
        link = d / "LA"
        link.symlink_to(real, target_is_directory=True)
        with mock.patch("msec.install.run", side_effect=_ok) as run, mock.patch("msec.install.time.sleep"), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(install.install(_cfg(d), entry=d / "bin/msec", launch_agents=link, uid=501), 1)
        self.assertEqual(list(real.iterdir()), [])
        run.assert_not_called()


class InstallBootstrapTest(unittest.TestCase):
    def _run_with(self, fake):
        d = Path(tempfile.mkdtemp())
        la = d / "LA"
        with mock.patch("msec.install.run", side_effect=fake) as run, \
                mock.patch("msec.install.time.sleep") as sleep, contextlib.redirect_stdout(io.StringIO()):
            rc = install.install(_cfg(d), entry=d / "bin/msec", launch_agents=la, uid=501)
        return rc, run, sleep

    @staticmethod
    def _bootstraps(run, label):
        return [c for c in run.call_args_list
                if c.args[0][1] == "bootstrap" and c.args[0][-1].endswith(f"{label}.plist")]

    def test_bootstrap_retried_once_then_succeeds(self):
        seen = {"n": 0}

        def fake(argv, **kw):
            if argv[1] == "bootstrap" and argv[-1].endswith("com.msec.nightly.plist"):
                seen["n"] += 1
                return _fail(argv) if seen["n"] == 1 else _ok(argv)
            return _ok(argv)

        rc, run, sleep = self._run_with(fake)
        self.assertEqual(rc, 0)
        self.assertEqual(len(self._bootstraps(run, "com.msec.nightly")), 2)
        sleep.assert_called_once_with(1)

    def test_second_job_bootstrap_fails_twice(self):
        def fake(argv, **kw):
            if argv[1] == "bootstrap" and argv[-1].endswith("com.msec.deliver.plist"):
                return _fail(argv)
            return _ok(argv)

        with mock.patch("builtins.print") as pr:
            rc, run, _ = self._run_with(fake)
        self.assertEqual(rc, 1)
        self.assertEqual(len(self._bootstraps(run, "com.msec.deliver")), 2)
        self.assertIn(mock.call("loaded so far: com.msec.nightly"), pr.call_args_list)


if __name__ == "__main__":
    unittest.main()

import plistlib
import tempfile
import unittest
from pathlib import Path

from msec import install
from msec.config import Config, Triage


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
        self.assertEqual(install.install(cfg, entry=d / "bin/msec", launch_agents=d / "LA", uid=501, dry_run=True), 0)
        self.assertFalse((d / "LA").exists())


if __name__ == "__main__":
    unittest.main()

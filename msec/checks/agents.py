"""Agent configs: Claude hooks/permissions/plugins/skills, MCP servers, Codex, OpenClaw, repo agent dirs, shell flags."""
import hashlib
import json
import os
import re
import tomllib
from pathlib import Path

from ..findings import Finding, not_scanned, result
from .persistence import RC_FILES

DANGEROUS_RULES = {"Bash", "Bash(*)", "Bash(*:*)", "*"}
DANGER_FLAGS = ("dangerously-skip-permissions", "dangerously-bypass-approvals-and-sandbox", "--yolo")
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "dist", "build", ".next", "vendor", "Library", "__pycache__"}
OPENCLAW_SKIP = {"runtime", "backups", "cache", "npm", "logs", "media", "browser"}
MCP_FILES = (("claude", ".claude.json"), ("cursor", ".cursor/mcp.json"),
             ("claude-desktop", "Library/Application Support/Claude/claude_desktop_config.json"))
LAUNCHERS = {"npx", "bunx", "pnpx", "uvx"}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def _load(path: Path, parse):
    """-> (data, unparseable). Missing file -> ({}, False). PermissionError propagates."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return {}, False
    try:
        data = parse(raw)
    except (ValueError, tomllib.TOMLDecodeError, UnicodeDecodeError):
        return {}, True
    return (data if isinstance(data, dict) else {}), not isinstance(data, dict)


def _bad(check: str, path: Path) -> Finding:
    return Finding(check, "agent-config", "medium", f"Unparseable agent config {path}",
                   {"file": str(path), "unparseable": True})


def _walk(root: Path, depth: int, skip: set[str], want, denied: list):
    stack = [(root, 0)]
    while stack:
        d, level = stack.pop()
        try:
            entries = list(os.scandir(d))
        except (FileNotFoundError, NotADirectoryError):
            continue
        except PermissionError:
            denied.append(str(d))
            continue
        for e in entries:
            if e.is_dir(follow_symlinks=False):
                if e.name not in skip and level < depth:
                    stack.append((Path(e.path), level + 1))
            elif e.is_file(follow_symlinks=False) and want(Path(e.path)):
                yield Path(e.path)


def _claude_file(p: Path, data: dict) -> list[Finding]:
    out = []
    for event, groups in (data.get("hooks") or {}).items():
        for g in groups if isinstance(groups, list) else []:
            g = g if isinstance(g, dict) else {}
            for h in g.get("hooks") or []:
                cmd = str((h or {}).get("command", ""))
                out.append(Finding("agents.claude.hook", "agent-config", "critical",
                                   f"Claude hook {event} [{g.get('matcher', '')}] in {p}: {cmd}",
                                   {"file": str(p), "event": str(event), "matcher": str(g.get("matcher", "")),
                                    "cmd": _sha(cmd.encode())}))
    perms = data.get("permissions") or {}
    for rule in perms.get("allow") or []:
        rule = str(rule)
        out.append(Finding("agents.claude.allow", "agent-permissions",
                           "high" if rule.strip() in DANGEROUS_RULES else "medium",
                           f"Claude allow rule {rule} in {p}", {"file": str(p), "rule": rule}))
    mode = perms.get("defaultMode")
    if mode:
        out.append(Finding("agents.claude.mode", "agent-permissions",
                           "high" if mode == "bypassPermissions" else "medium",
                           f"Claude defaultMode={mode} in {p}", {"file": str(p), "mode": str(mode)}))
    for plugin, on in (data.get("enabledPlugins") or {}).items():
        if on:
            out.append(Finding("agents.claude.plugin", "agent-config", "medium",
                               f"Claude plugin enabled: {plugin}", {"plugin": str(plugin)}))
    return out


def claude_settings(home: Path) -> list[Finding]:
    out = []
    for name in ("settings.json", "settings.local.json"):
        p = home / ".claude" / name
        data, bad = _load(p, json.loads)
        if bad:
            out.append(_bad("agents.claude", p))
            continue
        try:
            out += _claude_file(p, data)
        except (AttributeError, TypeError):     # wrong shape of a scanned config
            out.append(_bad("agents.claude", p))
    skills = home / ".claude" / "skills"
    for skill_md in sorted(skills.glob("*/SKILL.md")) if skills.is_dir() else []:
        try:
            digest = _sha(skill_md.read_bytes())
        except FileNotFoundError:       # dangling symlink
            continue
        out.append(Finding("agents.claude.skill", "agent-config", "medium", f"Claude skill {skill_md.parent.name}",
                           {"skill": skill_md.parent.name, "sha256": digest}))
    return out


def _unpinned(cmd: str, args: list[str]) -> bool:
    if any("@latest" in a for a in args):
        return True
    if Path(cmd).name in LAUNCHERS:
        pkgs = [a for a in args if not a.startswith("-")]
        return bool(pkgs) and not (re.search(r".@\d", pkgs[0]) or "==" in pkgs[0])
    return False


def _server_findings(client: str, scope: str, name, s) -> list[Finding]:
    s = s if isinstance(s, dict) else {}
    cmd, url = str(s.get("command", "")), str(s.get("url", ""))
    args = [str(a) for a in s.get("args") or []]
    key = {"client": client, "scope": scope, "name": str(name)}
    out = [Finding("agents.mcp", "agent-config", "medium", f"MCP server {name} ({client}, {scope}): {cmd or url}",
                   {**key, "def": _sha(json.dumps([cmd, args, url]).encode())})]
    if _unpinned(cmd, args):
        out.append(Finding("agents.mcp.unpinned", "agent-config", "medium",
                           f"MCP server {name} ({client}) runs an unpinned package", key))
    return out


def mcp_configs(home: Path) -> list[Finding]:
    out = []
    for client, rel in MCP_FILES:
        p = home / rel
        data, bad = _load(p, json.loads)
        if bad:
            out.append(_bad("agents.mcp", p))
            continue
        try:
            scopes = [("user", data.get("mcpServers") or {})]
            scopes += [(f"project:{proj}", pd.get("mcpServers") or {})
                       for proj, pd in (data.get("projects") or {}).items() if isinstance(pd, dict)]
            found = []
            for scope, servers in scopes:
                found += [f for name, s in servers.items() for f in _server_findings(client, scope, name, s)]
            out += found
        except (AttributeError, TypeError):
            out.append(_bad("agents.mcp", p))
    return out


def codex(home: Path) -> list[Finding]:
    p = home / ".codex" / "config.toml"
    data, bad = _load(p, lambda b: tomllib.loads(b.decode("utf-8")))
    if bad:
        return [_bad("agents.mcp", p)]
    out = []
    try:
        for name, s in (data.get("mcp_servers") or {}).items():
            out += _server_findings("codex", "user", name, s)
    except (AttributeError, TypeError):
        return [_bad("agents.mcp", p)]
    if data.get("sandbox_mode") == "danger-full-access":
        out.append(Finding("agents.codex", "agent-permissions", "high", "Codex sandbox_mode=danger-full-access",
                           {"file": str(p), "sandbox_mode": "danger-full-access"}))
    if data.get("approval_policy") == "never":
        out.append(Finding("agents.codex", "agent-permissions", "high", "Codex approval_policy=never",
                           {"file": str(p), "approval_policy": "never"}))
    return out


def openclaw(home: Path, denied: list) -> list[Finding]:
    root = home / ".openclaw"
    if not root.is_dir():
        return []
    out = []
    p = root / "openclaw.json"
    data, bad = _load(p, json.loads)
    if bad:
        out.append(_bad("agents.openclaw", p))
    profile = (data.get("tools") or {}).get("profile")
    if profile:
        out.append(Finding("agents.openclaw.tools", "agent-permissions", "medium",
                           f"OpenClaw tools profile = {profile}", {"profile": str(profile)}))
    for skill_md in _walk(root, 5, OPENCLAW_SKIP, lambda f: f.name == "SKILL.md", denied):
        out.append(Finding("agents.openclaw.skill", "agent-config", "medium", f"OpenClaw skill {skill_md.parent.name}",
                           {"path": str(skill_md), "sha256": _sha(skill_md.read_bytes())}))
    return out


def _agent_file(f: Path) -> bool:
    parts = f.parts
    return ".claude" in parts or ".vscode" in parts or tuple(parts[-3:-1]) == (".github", "workflows")


def repo_dirs(roots, denied: list) -> list[Finding]:
    out = []
    for root in roots:
        for f in _walk(root, 7, SKIP_DIRS, _agent_file, denied):
            high = (f.parent.name == ".claude" and f.name.startswith("settings")) or f.parent.name == "workflows"
            out.append(Finding("agents.repo", "agent-config", "high" if high else "medium",
                               f"Agent/CI file {f}", {"path": str(f), "sha256": _sha(f.read_bytes())}))
    return out


def rc_flags(home: Path) -> list[Finding]:
    out = []
    for name in RC_FILES:
        p = home / name
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if any(flag in line for flag in DANGER_FLAGS):
                out.append(Finding("agents.shell-flags", "agent-permissions", "high",
                                   f"{p}:{n} starts an agent with safety checks off",
                                   {"file": str(p), "line": _sha(line.strip().encode())}))
    return out


def _guard(check: str, fn):
    try:
        return result(check, fn())
    except PermissionError as e:
        return not_scanned(check, f"permission denied: {e.filename}")


def run(ctx) -> list:
    denied: list[str] = []
    out = [_guard("agents.claude", lambda: claude_settings(ctx.home)),
           _guard("agents.mcp", lambda: mcp_configs(ctx.home) + codex(ctx.home)),
           _guard("agents.openclaw", lambda: openclaw(ctx.home, denied)),
           _guard("agents.repo", lambda: repo_dirs(ctx.scan_roots, denied)),
           _guard("agents.shell-flags", lambda: rc_flags(ctx.home))]
    if denied:
        out.append(not_scanned("agents.partial", f"{len(denied)} dirs unreadable, e.g. {denied[0]}"))
    return out

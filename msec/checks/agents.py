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
REPO_VOLATILE = {"worktrees", "todos", "shell-snapshots", "scratchpad", "memory", "projects", "logs", "cache"}
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
    except (ValueError, tomllib.TOMLDecodeError, UnicodeDecodeError, RecursionError):
        return {}, True
    return (data if isinstance(data, dict) else {}), not isinstance(data, dict)


def _bad(check: str, path: Path) -> Finding:
    return Finding(check, "agent-config", "medium", f"Unparseable agent config {path}",
                   {"file": str(path), "unparseable": True})


def _walk(root: Path, depth: int, skip: set[str], want, denied: list, skip_pair=None):
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
            if e.is_symlink():      # Claude Code follows links; report them, never descend
                if not (skip_pair and skip_pair(d.name, e.name)) and want(Path(e.path)):
                    yield Path(e.path)
            elif e.is_dir(follow_symlinks=False):
                if e.name not in skip and level < depth and not (skip_pair and skip_pair(d.name, e.name)):
                    stack.append((Path(e.path), level + 1))
            elif e.is_file(follow_symlinks=False) and not (skip_pair and skip_pair(d.name, e.name)) and want(Path(e.path)):
                yield Path(e.path)


def _claude_file(p: Path, data: dict) -> list[Finding]:
    out = []
    hooks = data.get("hooks") or {}
    perms = data.get("permissions") or {}
    allow = perms.get("allow") if isinstance(perms, dict) else None
    if not isinstance(hooks, dict) or not isinstance(perms, dict) or not isinstance(allow or [], list):
        raise TypeError("bad shape")
    for event, groups in hooks.items():
        if not isinstance(groups, list):
            raise TypeError("bad shape")
        for g in groups:
            if not isinstance(g, dict):
                raise TypeError("bad shape")
            for h in g.get("hooks") or []:
                cmd = str((h or {}).get("command", ""))
                out.append(Finding("agents.claude.hook", "agent-config", "critical",
                                   f"Claude hook {event} [{g.get('matcher', '')}] in {p}: {cmd}",
                                   {"file": str(p), "event": str(event), "matcher": str(g.get("matcher", "")),
                                    "cmd": _sha(cmd.encode())}))
    for rule in allow or []:
        rule = str(rule)
        out.append(Finding("agents.claude.allow", "agent-permissions",
                           "high" if rule.strip() in DANGEROUS_RULES else "medium",
                           f"Claude allow rule {rule} in {p}", {"file": str(p), "rule": _sha(rule.encode())}))
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
    raw_args = s.get("args") or []
    if not isinstance(raw_args, list):
        raise TypeError("bad shape")
    args = [str(a) for a in raw_args]
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
    tools = data.get("tools") or {}
    if not isinstance(tools, dict):
        out.append(_bad("agents.openclaw", p))
        tools = {}
    profile = tools.get("profile")
    if profile:
        out.append(Finding("agents.openclaw.tools", "agent-permissions", "medium",
                           f"OpenClaw tools profile = {profile}", {"profile": str(profile)}))
    for skill_md in _walk(root, 5, OPENCLAW_SKIP, lambda f: f.name == "SKILL.md", denied):
        key = _file_key(skill_md, denied)
        if key:
            out.append(Finding("agents.openclaw.skill", "agent-config", "medium",
                               f"OpenClaw skill {skill_md.parent.name}", key))
    return out


def _read(f: Path, denied: list):
    """File bytes, or None if it vanished (skipped) or is unreadable (recorded in denied)."""
    try:
        return f.read_bytes()
    except FileNotFoundError:
        return None
    except OSError:
        denied.append(str(f))
        return None


def _file_key(f: Path, denied: list):
    """Finding key for a file or symlink; None if it cannot be read."""
    if f.is_symlink():
        target = os.readlink(f)
        raw = _read(f, denied) if os.path.isfile(f) else b""
        if raw is None:
            return None
        return {"path": str(f), "target": target, "sha256": _sha(raw) if os.path.isfile(f) else ""}
    raw = _read(f, denied)
    return None if raw is None else {"path": str(f), "sha256": _sha(raw)}


def _agent_file(f: Path) -> bool:
    parts = f.parts
    return ".claude" in parts or ".vscode" in parts or tuple(parts[-3:-1]) == (".github", "workflows")


def _repo_skip(parent: str, name: str) -> bool:
    return parent == ".claude" and (name in REPO_VOLATILE or name.endswith(".lock"))


def _skill_dir(f: Path):
    """<repo>/.claude/skills/<name> for a file inside a skill subdir, else None."""
    parts = f.parts
    for i in range(len(parts) - 4, -1, -1):
        if parts[i] == ".claude" and parts[i + 1] == "skills":
            return Path(*parts[:i + 3])
    return None


def repo_dirs(roots, denied: list) -> list[Finding]:
    out = []
    skills: dict[Path, list] = {}
    for root in roots:
        for f in _walk(root, 7, SKIP_DIRS, _agent_file, denied, _repo_skip):
            key = _file_key(f, denied)
            if key is None:
                continue
            sd = _skill_dir(f)
            if sd:
                skills.setdefault(sd, []).append((str(f.relative_to(sd)), key.get("target", ""), key["sha256"]))
                continue
            high = (f.parent.name == ".claude" and f.name.startswith("settings")) or f.parent.name == "workflows"
            title = f"Agent/CI symlink {f} -> {key['target']}" if "target" in key else f"Agent/CI file {f}"
            out.append(Finding("agents.repo", "agent-config", "high" if high else "medium", title, key))
    for sd, files in sorted(skills.items()):
        out.append(Finding("agents.repo", "agent-config", "medium", f"Agent skill {sd}",
                           {"path": str(sd), "sha256": _sha(json.dumps(sorted(files)).encode())}))
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

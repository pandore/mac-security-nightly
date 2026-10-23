# mac-security-nightly

A nightly, non-remediating security check for a macOS developer machine that runs AI coding agents.

Every night it looks for what 2026-era attacks on developer Macs actually change — new autorun items, injected agent hooks and MCP servers, malicious or vulnerable packages, npm-worm leftovers — compares the result with a baseline you reviewed, and tells you in the morning only when something **new and dangerous** appeared. Claude explains the findings in plain language, but runs with **no tools at all**, so it cannot be talked into doing anything.

> **Status: beta.** Built and tested on one Apple Silicon Mac (macOS 27, Homebrew in `/opt/homebrew`). Notifications, the report and the model's explanations are in **Ukrainian**. Expect rough edges on other setups — issues and PRs welcome.

```
🛡 Mac 24.10: 🔴1 🟠0 🟡2 — persistence, agent-config. Звіт на маку.
```

## How it works

```
LaunchAgent 04:00 ─► msec nightly
   1. collect   deterministic checks, fixed argv, scrubbed env          ─► findings (severity set in code)
   2. classify  against seen.json (what was shown) + baseline.json (what you accepted)
   3. triage    claude -p with NO tools, findings JSON on stdin           ─► schema-validated explanations
   4. write     report.md, summary.json, findings.json (atomic, 0600)
LaunchAgent 08:30 / 11:00 ─► msec deliver ─► macOS notification, at most once per day
```

Nothing is ever fixed automatically. The report lists ready-made fix commands (built by the check code, never by the model); you run them yourself.

## What it checks

| Area | Checks | Severity rules |
|---|---|---|
| Autorun | launchd plists (user + system), Background Task Management items (`sfltool dumpbtm`), crontab, shell rc files | 🔴 unsigned / ad-hoc / invalid signature / launched through an interpreter (`sh`, `python`, `osascript`, …); 🟡 new signed item |
| Agent configs | Claude Code hooks, allow rules, `defaultMode`, plugins, skills, agents/commands/hooks; MCP servers in Claude, Claude Desktop, Cursor, Codex; Codex `sandbox_mode` / `approval_policy`; OpenClaw tools and skills; `.claude/`, `.vscode/`, `.mcp.json`, `.github/workflows` inside your repos; shell aliases that turn agent safety off | 🔴 new hook; 🟠 `Bash(*)`-style rules, bypass modes, repo `settings*.json` / workflows / `.mcp.json`; 🟡 other changes, unpinned `npx …@latest` MCP servers |
| Packages & updates | `brew vulns`, `osv-scanner` over your repos' lockfiles, `grype` over globally installed npm packages, `npm -g outdated`, `softwareupdate -l`, npm-worm IOC files via Spotlight | 🔴 known-malicious package (OSV `MAL-…`) or IOC file; 🟠 high/critical CVE **with a fix** in installed software; ⚪ lockfile CVEs (hygiene, never alert) |
| Coverage | any check that could not run | 🟡 once, so "quiet" never means "not checked" |

Signatures are **verified** (`codesign --verify --strict`, Apple items additionally against `anchor apple`), not just displayed.

## Safety model

- **No shell anywhere.** Every external command runs with a fixed argv, a scrubbed environment (no inherited tokens; `HOME`/`TMPDIR`/caches inside the state dir) and a timeout that kills the whole process group.
- **The model has no tools.** `claude -p --tools "" --strict-mcp-config --mcp-config '{"mcpServers":{}}' --setting-sources ""`, structured output enforced with `--json-schema`, a spend cap, and validation of every field. It never sees file contents or secret values: titles are masked (URL query strings, tokens with known prefixes, `KEY=value`, `Bearer`/`Basic` values, long random strings).
- **The model cannot change anything that matters.** Severity, counts and the outward message come from check code only; the notification text is built from counts and a fixed category list.
- **Baseline is explicit.** Only `msec accept` changes it, with a reason and an expiry date, and every acceptance is logged. A changed item (new fingerprint — e.g. an edited plist, a changed hook command, a severity escalation) alerts again.
- **State** lives in `~/.local/state/mac-security/` (dirs 0700, files 0600, writes refuse symlinks).
- **Residual risk, stated plainly:** this is a detection aid, not an EDR. Malware already running as your user can tamper with a local monitor.

## What leaves the machine

| Check | Egress |
|---|---|
| persistence.*, agents.*, ioc.files | none |
| packages.brew (`brew vulns`) | formula names and versions to OSV.dev |
| packages.osv (`osv-scanner`) | package names and versions to OSV.dev |
| packages.grype | vulnerability DB download only; package list stays local |
| updates.npm | package names to the npm registry |
| updates.macos | Apple Software Update service |
| triage (`claude -p`, no tools) | redacted findings JSON (titles, paths, versions; never secret values or file contents) to Anthropic |
| delivery (macos-notify) | none |

Set `[triage] enabled = false` to keep everything local.

## Requirements

- macOS on Apple Silicon with [Homebrew](https://brew.sh) in `/opt/homebrew`
- Homebrew Python 3.11+ (`/opt/homebrew/bin/python3`; the Xcode `python3` is too old). No third-party Python packages.
- Optional: [Claude Code](https://docs.claude.com/en/docs/claude-code) CLI for triage (subscription login or a dedicated API key)

## Install

```sh
git clone https://github.com/pandore/mac-security-nightly.git ~/Repos/mac-security-nightly
cd ~/Repos/mac-security-nightly
brew bundle --file=Brewfile && brew pin osv-scanner grype   # pinned: upgrade scanners deliberately

mkdir -p ~/.config/mac-security && chmod 700 ~/.config/mac-security
cp config.example.toml ~/.config/mac-security/config.toml && chmod 600 ~/.config/mac-security/config.toml
$EDITOR ~/.config/mac-security/config.toml   # scan_roots, timezone, claude_path (`which claude`)
bin/msec status                               # "no runs yet" means the config loads
```

Config keys: `scan_roots` (absolute dirs with your repos), `timezone`, `deliver_after` (`HH:MM`), `[triage]` (`enabled`, `claude_path`, `auth = "subscription" | "api-key"`, `model`, `max_budget_usd`, `api_key_keychain_service`), `[delivery] adapters = ["macos-notify"]`. Unknown keys are rejected.

With `auth = "api-key"` the CLI runs in `--bare` mode and reads the key from a Keychain item: `security add-generic-password -s msec-anthropic -a msec -w` (give that key its own spend limit).

## First run and baseline

The first run reports everything as new (thousands of items on a busy dev machine — mostly inventory).

```sh
bin/msec nightly --force          # 3–10 minutes
bin/msec status                   # summary + path to report.md
open ~/.local/state/mac-security/reports/$(date +%F)/report.md
```

1. Go through **every 🔴 one by one**. Remove what you don't recognise (the report shows the command), accept what is yours:
   `bin/msec accept <fingerprint> --reason "my backup script" --days 90`
2. Only after that, accept the rest as your baseline:
   `bin/msec accept --all-seen --reason "initial baseline" --days 90` (asks you to type `YES`).
   Accepting the vulnerable-package findings for a shorter period (e.g. 30 days) turns them into a reminder.

## Schedule

```sh
bin/msec install --dry-run && bin/msec install       # two user LaunchAgents: 04:00 and deliver_after (+150 min)
launchctl kickstart gui/$(id -u)/com.msec.deliver    # test the notification from launchd
```

The next run reports msec's own two LaunchAgents as 🔴 (they start through `python3`); accept them. If the banner never appears, allow notifications for **Script Editor** in System Settings → Notifications. If the Mac sleeps at 04:00, launchd runs the check after wake; delivery waits for it.

## Every morning

| You see | Meaning | Do |
|---|---|---|
| nothing | checked, nothing new and dangerous | nothing |
| `🛡 Mac DD.MM: 🔴N 🟠N 🟡N — …` | new findings | read the report |
| `(+N відкритих 🔴)` | criticals still neither removed nor accepted | fix or accept |
| `⚠ Нічна перевірка мака не відпрацювала` | no run, or it failed | `bin/msec status` |
| `⚠ msec: конфіг не читається` | config broken | `bin/msec status` |

## Known limitations

- Runs as your user without `sudo`: root-only items (e.g. Remote Login state, some system daemons' details) are not visible.
- The "did not run" alert is local; if the Mac is off, nobody tells you (a remote dead-man is on the roadmap).
- The IOC file search needs Spotlight indexing; when it is off, the check reports itself as not scanned.
- A LaunchAgent may have fewer macOS privacy (TCC) permissions than your terminal: compare `not_scanned` after the first scheduled night with your manual run.
- Lockfile CVEs never alert by design; only installed software with an available fix does.

## Roadmap

- More checks: secrets in repos and dotfiles, OS settings drift, listening ports, unsigned running processes, app versions, TCC permissions, browser extensions, Time Machine age, SSH keys without a passphrase.
- Remote receipt + dead-man and a Telegram adapter.
- Checks defined as data, so you can switch off what your machine doesn't have.

## Development

```sh
/opt/homebrew/bin/python3 -m unittest discover -s tests -v
```

Stdlib only. Tests use temp dirs and synthetic fixtures and never run the real scanners, launchctl or claude.

## License

[MIT](LICENSE)

# mac-security-nightly

Nightly, non-remediating security check for a macOS developer machine.
Deterministic collectors → typed findings (severity set in code) → Claude with no tools explains them → notification only when something new and dangerous appears.

Safety model: scanners run with fixed argv and a scrubbed environment; the model gets only redacted JSON and has no tools; outward messages are built from counts and a fixed category list.

Personal settings live in `~/.config/mac-security/config.toml` (see `config.example.toml`); state and reports in `~/.local/state/mac-security/`. Nothing personal is stored in this repo.

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

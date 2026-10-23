# mac-security-nightly

Nightly, non-remediating security check for a macOS developer machine.
Deterministic collectors → typed findings (severity set in code) → Claude with no tools explains them → notification only when something new and dangerous appears.

Safety model: scanners run with fixed argv and a scrubbed environment; the model gets only redacted JSON and has no tools; outward messages are built from counts and a fixed category list.

Personal settings live in `~/.config/mac-security/config.toml` (see `config.example.toml`); state and reports in `~/.local/state/mac-security/`. Nothing personal is stored in this repo.

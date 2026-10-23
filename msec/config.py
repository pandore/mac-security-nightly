"""Load and validate ~/.config/mac-security/config.toml. Personal values live only there."""
import re
import tomllib
from dataclasses import dataclass, fields
from pathlib import Path
from zoneinfo import ZoneInfo

CONFIG_PATH = Path.home() / ".config/mac-security/config.toml"
STATE_DIR = Path.home() / ".local/state/mac-security"
ADAPTERS = frozenset({"macos-notify"})
AUTH_MODES = frozenset({"subscription", "api-key"})


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Triage:
    enabled: bool = True
    claude_path: str = ""
    auth: str = "subscription"
    model: str = "claude-sonnet-5-5"
    max_budget_usd: float = 0.5
    api_key_keychain_service: str = "msec-anthropic"


@dataclass(frozen=True)
class Config:
    scan_roots: tuple[Path, ...]
    timezone: str
    deliver_after: str
    triage: Triage
    adapters: tuple[str, ...]
    state_dir: Path


def _only_known(table: dict, allowed: set[str], where: str) -> None:
    unknown = set(table) - allowed
    if unknown:
        raise ConfigError(f"{where}: unknown keys {sorted(unknown)}")


def _triage(t: dict) -> Triage:
    _only_known(t, {f.name for f in fields(Triage)}, "triage")
    tri = Triage(**t)
    if not isinstance(tri.enabled, bool):
        raise ConfigError("triage.enabled: must be true or false")
    if tri.auth not in AUTH_MODES:
        raise ConfigError(f"triage.auth: one of {sorted(AUTH_MODES)}")
    if tri.enabled and not (Path(tri.claude_path).is_absolute() and Path(tri.claude_path).exists()):
        raise ConfigError("triage.claude_path: absolute path to an existing claude binary")
    if not (isinstance(tri.model, str) and re.fullmatch(r"[a-z0-9][a-z0-9.-]{2,63}", tri.model)):
        raise ConfigError("triage.model: invalid model id")
    if isinstance(tri.max_budget_usd, bool) or not isinstance(tri.max_budget_usd, (int, float)) \
            or not 0 < tri.max_budget_usd <= 5:
        raise ConfigError("triage.max_budget_usd: must be in (0, 5]")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", str(tri.api_key_keychain_service)):
        raise ConfigError("triage.api_key_keychain_service: invalid name")
    return tri


def load(path: Path = CONFIG_PATH, state_dir: Path = STATE_DIR) -> Config:
    try:
        data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise ConfigError(f"cannot read {path}: {e}") from e
    _only_known(data, {"scan_roots", "timezone", "deliver_after", "triage", "delivery"}, "config")

    roots = []
    for raw in data.get("scan_roots", []):
        if not (isinstance(raw, str) and Path(raw).is_absolute() and Path(raw).is_dir()):
            raise ConfigError(f"scan_roots: not an existing absolute dir: {raw!r}")
        roots.append(Path(raw))
    if not roots:
        raise ConfigError("scan_roots: at least one root is required")

    tz = data.get("timezone", "Europe/Lisbon")
    try:
        ZoneInfo(tz)
    except Exception as e:
        raise ConfigError(f"timezone: {tz!r} is not a valid zone") from e

    after = data.get("deliver_after", "08:30")
    if not (isinstance(after, str) and re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", after)):
        raise ConfigError(f"deliver_after: expected HH:MM, got {after!r}")

    delivery = data.get("delivery", {})
    _only_known(delivery, {"adapters"}, "delivery")
    adapters = tuple(delivery.get("adapters", ["macos-notify"]))
    if not adapters or set(adapters) - ADAPTERS:
        raise ConfigError(f"delivery.adapters: allowed {sorted(ADAPTERS)}, got {list(adapters)}")

    return Config(tuple(roots), tz, after, _triage(data.get("triage", {})), adapters, Path(state_dir))

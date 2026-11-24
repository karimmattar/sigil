"""Per-OS locations for the config file and logs (Windows, macOS, Linux/XDG).

Every function takes the OS name, environment and home directory as parameters
(defaulting to the real ones) so the logic can be tested for all platforms anywhere.
"""

from __future__ import annotations

import os
import platform
from collections.abc import Mapping
from pathlib import Path

APP_DIR_NAME = "Sigil"  # Windows / macOS style
APP_SLUG = "sigil"  # Linux / XDG style
CONFIG_FILE_NAME = "config.toml"


def _defaults(
    system: str | None, env: Mapping[str, str] | None, home: Path | None
) -> tuple[str, Mapping[str, str], Path]:
    return (
        system or platform.system(),
        os.environ if env is None else env,
        Path.home() if home is None else home,
    )


def config_dir(
    system: str | None = None, env: Mapping[str, str] | None = None, home: Path | None = None
) -> Path:
    """Directory holding ``config.toml``."""
    system, env, home = _defaults(system, env, home)
    if system == "Windows":
        return Path(env.get("APPDATA", home / "AppData" / "Roaming")) / APP_DIR_NAME
    if system == "Darwin":
        return home / "Library" / "Application Support" / APP_DIR_NAME
    return Path(env.get("XDG_CONFIG_HOME") or home / ".config") / APP_SLUG


def log_dir(
    system: str | None = None, env: Mapping[str, str] | None = None, home: Path | None = None
) -> Path:
    """Directory for ``agent.log`` and ``audit.log``."""
    system, env, home = _defaults(system, env, home)
    if system == "Windows":
        return Path(env.get("LOCALAPPDATA", home / "AppData" / "Local")) / APP_DIR_NAME / "logs"
    if system == "Darwin":
        return home / "Library" / "Logs" / APP_DIR_NAME
    return Path(env.get("XDG_STATE_HOME") or home / ".local" / "state") / APP_SLUG / "logs"


def default_config_file(
    system: str | None = None, env: Mapping[str, str] | None = None, home: Path | None = None
) -> Path:
    """Full path of the default config file."""
    return config_dir(system, env, home) / CONFIG_FILE_NAME

"""Start the agent at user login — one strategy per operating system.

* Windows: ``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`` registry value
* macOS:   ``~/Library/LaunchAgents/<label>.plist`` (launchd user agent)
* Linux:   ``~/.config/autostart/sigil.desktop`` (XDG autostart, all desktops)

Everything is per-user; no administrator rights are needed.
"""

from __future__ import annotations

import os
import platform
import plistlib
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol

APP_LABEL = "com.sigil.agent"
RUN_VALUE_NAME = "Sigil"
_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def launch_command() -> list[str]:
    """Command that starts the agent: the frozen executable, or ``python -m sigil``."""
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, "-m", "sigil", "serve"]


class AutostartBackend(Protocol):
    """Per-OS start-at-login strategy."""

    def is_enabled(self) -> bool: ...

    def enable(self, command: Sequence[str]) -> str:
        """Register ``command``; returns a human-readable description of what was done."""
        ...

    def disable(self) -> str: ...


def _import_winreg() -> Any:
    import winreg  # noqa: PLC0415 - only exists on Windows

    return winreg


class WindowsRunKeyAutostart:
    """``HKCU\\...\\Run`` value (``winreg`` is injectable for tests on other OSes)."""

    def __init__(self, winreg_module: Any | None = None) -> None:
        self._reg: Any = winreg_module if winreg_module is not None else _import_winreg()

    def is_enabled(self) -> bool:
        try:
            with self._reg.OpenKey(self._reg.HKEY_CURRENT_USER, _RUN_KEY) as key:
                self._reg.QueryValueEx(key, RUN_VALUE_NAME)
                return True
        except OSError:
            return False

    def enable(self, command: Sequence[str]) -> str:
        value = subprocess.list2cmdline(list(command))
        with self._reg.CreateKey(self._reg.HKEY_CURRENT_USER, _RUN_KEY) as key:
            self._reg.SetValueEx(key, RUN_VALUE_NAME, 0, self._reg.REG_SZ, value)
        return f"Registered HKCU\\{_RUN_KEY}\\{RUN_VALUE_NAME} = {value}"

    def disable(self) -> str:
        try:
            with self._reg.OpenKey(
                self._reg.HKEY_CURRENT_USER, _RUN_KEY, 0, self._reg.KEY_SET_VALUE
            ) as key:
                self._reg.DeleteValue(key, RUN_VALUE_NAME)
        except OSError:
            return "Start at login was not enabled."
        return f"Removed HKCU\\{_RUN_KEY}\\{RUN_VALUE_NAME}"


class MacLaunchAgentAutostart:
    """launchd user agent; restarts the agent if it crashes (but not after a clean Quit)."""

    def __init__(self, home: Path | None = None, label: str = APP_LABEL) -> None:
        self._label = label
        self._path = (home or Path.home()) / "Library" / "LaunchAgents" / f"{label}.plist"

    @property
    def path(self) -> Path:
        return self._path

    def is_enabled(self) -> bool:
        return self._path.is_file()

    def enable(self, command: Sequence[str]) -> str:
        plist = {
            "Label": self._label,
            "ProgramArguments": list(command),
            "RunAtLoad": True,
            "KeepAlive": {"SuccessfulExit": False},
            "ProcessType": "Interactive",
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_bytes(plistlib.dumps(plist))
        return f"Created {self._path} (active from next login)"

    def disable(self) -> str:
        if not self._path.exists():
            return "Start at login was not enabled."
        self._path.unlink()
        return f"Removed {self._path}"


def _desktop_exec_quote(arg: str) -> str:
    """Quote one argument for a ``.desktop`` ``Exec=`` line (freedesktop.org spec)."""
    if arg and not any(ch in arg for ch in " \t\n\"'\\><~|&;$*?#()`"):
        return arg
    escaped = "".join("\\" + ch if ch in '"`$\\' else ch for ch in arg)
    return f'"{escaped}"'


class XdgAutostart:
    """XDG autostart entry understood by GNOME, KDE, XFCE, Cinnamon, MATE…"""

    def __init__(self, env: Mapping[str, str] | None = None, home: Path | None = None) -> None:
        env = os.environ if env is None else env
        base = Path(env.get("XDG_CONFIG_HOME") or (home or Path.home()) / ".config")
        self._path = base / "autostart" / "sigil.desktop"

    @property
    def path(self) -> Path:
        return self._path

    def is_enabled(self) -> bool:
        return self._path.is_file()

    def enable(self, command: Sequence[str]) -> str:
        exec_line = " ".join(_desktop_exec_quote(a) for a in command)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            "[Desktop Entry]\n"
            "Type=Application\n"
            "Name=Sigil\n"
            "Comment=Local bridge between the web system and your signing token\n"
            f"Exec={exec_line}\n"
            "Terminal=false\n"
            "X-GNOME-Autostart-enabled=true\n",
            encoding="utf-8",
        )
        return f"Created {self._path}"

    def disable(self) -> str:
        if not self._path.exists():
            return "Start at login was not enabled."
        self._path.unlink()
        return f"Removed {self._path}"


def autostart_backend(system: str | None = None) -> AutostartBackend:
    """The strategy for the current (or given) operating system."""
    system = system or platform.system()
    if system == "Windows":
        return WindowsRunKeyAutostart()
    if system == "Darwin":
        return MacLaunchAgentAutostart()
    return XdgAutostart()

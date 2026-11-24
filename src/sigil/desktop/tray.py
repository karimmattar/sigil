"""System-tray / menu-bar icon (optional ``[tray]`` extra: pystray + Pillow).

The icon colour shows the state at a glance and the menu offers status, the API docs,
the log folder, a "Start at login" toggle and Quit. pystray must own the main thread
(a macOS requirement), so the HTTP server runs in a background thread.
"""

from __future__ import annotations

import enum
import logging
import os
import platform
import subprocess
import sys
import threading
import webbrowser
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sigil.application.token_service import TokenService
from sigil.domain.errors import AgentError, TokenBusyError
from sigil.infrastructure.config import AgentSettings

from .autostart import AutostartBackend, launch_command
from .server import AgentServer

logger = logging.getLogger(__name__)

POLL_SECONDS = 5.0


class TrayState(enum.Enum):
    """Icon states and their colours."""

    STARTING = "#9e9e9e"
    READY = "#2e7d32"  # token connected
    NO_TOKEN = "#f9a825"  # noqa: S105 - a colour, not a secret; driver OK, no token
    ERROR = "#c62828"  # no driver / driver error


def tray_support(system: str | None = None, env: dict[str, str] | None = None) -> tuple[bool, str]:
    """Whether a tray icon can be shown here; the reason when it cannot."""
    system = system or platform.system()
    env = dict(os.environ) if env is None else env
    # Check the display first: on Linux, importing pystray without one can itself fail.
    if system == "Linux" and not (env.get("DISPLAY") or env.get("WAYLAND_DISPLAY")):
        return False, "no graphical session (DISPLAY/WAYLAND_DISPLAY unset)"
    try:
        import PIL  # noqa: F401, PLC0415
        import pystray  # noqa: F401, PLC0415
    except Exception as exc:  # ImportError or a backend failing to initialise
        return (
            False,
            f"tray extras unavailable ({exc}); install the [tray] extra",
        )
    return True, ""


def describe_state(tokens: TokenService) -> tuple[TrayState, str]:
    """Compute the icon state and status line from the token service."""
    driver = tokens.driver_status()
    if not driver.loaded:
        return TrayState.ERROR, driver.error or "Token driver not found"
    found = tokens.list_tokens()
    if not found:
        return TrayState.NO_TOKEN, "No token connected"
    names = ", ".join(t.label or t.serial for t in found)
    return TrayState.READY, f"Token ready: {names}"


def make_icon_image(state: TrayState, size: int = 64) -> Any:
    """Draw a simple key glyph in the state's colour (no image files to ship)."""
    from PIL import Image, ImageDraw  # noqa: PLC0415

    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    s = size / 64
    draw.ellipse((4 * s, 4 * s, 60 * s, 60 * s), fill=state.value)
    white = (255, 255, 255, 255)
    draw.ellipse((14 * s, 22 * s, 34 * s, 42 * s), outline=white, width=max(1, int(5 * s)))
    draw.rectangle((33 * s, 29 * s, 52 * s, 35 * s), fill=white)
    draw.rectangle((44 * s, 35 * s, 49 * s, 42 * s), fill=white)
    return image


def open_folder(path: Path) -> None:
    """Open a folder in the platform file manager."""
    # sys.platform (not platform.system()) so mypy type-checks each branch per target OS.
    if sys.platform == "win32":
        os.startfile(path)  # noqa: S606 - local folder
    else:
        opener = "open" if sys.platform == "darwin" else "xdg-open"
        subprocess.Popen([opener, str(path)])  # noqa: S603 - fixed program, local path


def _import_pystray() -> Any:
    import pystray  # noqa: PLC0415 - optional dependency

    return pystray


class TrayApp:
    """Owns the tray icon, the status poller and the background HTTP server."""

    def __init__(
        self,
        server: AgentServer,
        tokens: TokenService,
        settings: AgentSettings,
        autostart: AutostartBackend,
        log_dir: Path | None,
        *,
        pystray_module: Any | None = None,
        open_url: Callable[[str], Any] = webbrowser.open,
        open_dir: Callable[[Path], None] = open_folder,
    ) -> None:
        self._pystray: Any = pystray_module if pystray_module is not None else _import_pystray()
        self._server = server
        self._tokens = tokens
        self._settings = settings
        self._autostart = autostart
        self._log_dir = log_dir
        self._open_url = open_url
        self._open_dir = open_dir
        self._stop = threading.Event()
        self._state = TrayState.STARTING
        self._status = "Starting…"
        self._icon: Any = None

    # ------------------------------------------------------------------ lifecycle

    def run(self) -> int:
        """Start the server, show the icon and block until the user chooses Quit."""
        self._server.start_background()
        self._icon = self._pystray.Icon(
            "sigil",
            icon=make_icon_image(self._state),
            title="Sigil",
            menu=self.build_menu(),
        )
        poller = threading.Thread(target=self._poll, name="tray-status", daemon=True)
        poller.start()
        try:
            self._icon.run()
        finally:
            self._stop.set()
            self._server.stop()
        return 0

    def refresh(self) -> None:
        """Re-read the token state and update icon, tooltip and menu."""
        try:
            state, status = describe_state(self._tokens)
        except TokenBusyError:
            return  # a signature is running; keep the previous state
        except AgentError as exc:
            state, status = TrayState.ERROR, exc.message
        self._state, self._status = state, status
        if self._icon is not None:
            self._icon.icon = make_icon_image(state)
            self._icon.title = f"Sigil — {status}"
            self._icon.update_menu()

    def _poll(self) -> None:
        while not self._stop.is_set():
            try:
                self.refresh()
            except Exception:  # the poller must never die silently
                logger.exception("Tray status refresh failed")
            self._stop.wait(POLL_SECONDS)

    # ------------------------------------------------------------------ menu

    def build_menu(self) -> Any:
        item, menu = self._pystray.MenuItem, self._pystray.Menu
        return menu(
            item(lambda _: self._status, None, enabled=False),
            item(f"Listening on {self._settings.base_url}", None, enabled=False),
            menu.SEPARATOR,
            item("Open API docs", self._open_docs, visible=self._settings.enable_docs),
            item("Open logs folder", self._open_logs, visible=self._log_dir is not None),
            item("Start at login", self._toggle_autostart, checked=lambda _: self._autostart_on()),
            menu.SEPARATOR,
            item("Quit", self._quit),
        )

    def _open_docs(self, *_: Any) -> None:
        self._open_url(f"{self._settings.base_url}/docs")

    def _open_logs(self, *_: Any) -> None:
        if self._log_dir is not None:
            self._open_dir(self._log_dir)

    def _autostart_on(self) -> bool:
        try:
            return self._autostart.is_enabled()
        except OSError:
            return False

    def _toggle_autostart(self, *_: Any) -> None:
        try:
            if self._autostart.is_enabled():
                logger.info(self._autostart.disable())
            else:
                logger.info(self._autostart.enable(launch_command()))
        except OSError:
            logger.exception("Could not change the start-at-login setting")

    def _quit(self, *_: Any) -> None:
        self._stop.set()
        if self._icon is not None:
            self._icon.stop()

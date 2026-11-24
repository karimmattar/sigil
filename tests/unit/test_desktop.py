"""Desktop layer: CLI, server runner, tray (fake pystray) and start-at-login strategies."""

from __future__ import annotations

import json
import plistlib
import socket
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from sigil import display_version
from sigil.application.token_service import TokenService
from sigil.desktop import autostart as autostart_module
from sigil.desktop import cli
from sigil.desktop.autostart import (
    MacLaunchAgentAutostart,
    WindowsRunKeyAutostart,
    XdgAutostart,
    _desktop_exec_quote,
    autostart_backend,
    launch_command,
)
from sigil.desktop.server import AgentServer, PortState, probe_port
from sigil.desktop.tray import (
    TrayApp,
    TrayState,
    describe_state,
    make_icon_image,
    tray_support,
)
from sigil.domain.errors import DriverNotFoundError, TokenBusyError
from sigil.domain.models import DriverStatus
from sigil.infrastructure.config import AgentSettings
from tests.support.fakes import FakeGateway, token_info
from tests.support.harness import Harness

# --------------------------------------------------------------------------- autostart


class FakeWinreg:
    HKEY_CURRENT_USER = "HKCU"
    KEY_SET_VALUE = 2
    REG_SZ = 1

    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    class _Key:
        def __enter__(self) -> FakeWinreg._Key:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

    def OpenKey(self, *args: Any) -> _Key:
        return self._Key()

    CreateKey = OpenKey

    def QueryValueEx(self, key: Any, name: str) -> tuple[str, int]:
        if name not in self.values:
            raise FileNotFoundError(name)
        return self.values[name], self.REG_SZ

    def SetValueEx(self, key: Any, name: str, reserved: int, kind: int, value: str) -> None:
        self.values[name] = value

    def DeleteValue(self, key: Any, name: str) -> None:
        if name not in self.values:
            raise FileNotFoundError(name)
        del self.values[name]


class TestAutostart:
    def test_macos_launch_agent(self, tmp_path: Path) -> None:
        backend = MacLaunchAgentAutostart(home=tmp_path)
        assert not backend.is_enabled()
        backend.enable(["/Applications/Sigil.app/Contents/MacOS/sigil"])
        plist = plistlib.loads(backend.path.read_bytes())
        assert plist["ProgramArguments"] == ["/Applications/Sigil.app/Contents/MacOS/sigil"]
        assert plist["RunAtLoad"] is True
        assert plist["KeepAlive"] == {"SuccessfulExit": False}
        assert backend.is_enabled()
        assert "Removed" in backend.disable()
        assert "was not enabled" in backend.disable()

    def test_linux_xdg_entry_quotes_arguments(self, tmp_path: Path) -> None:
        backend = XdgAutostart(env={"XDG_CONFIG_HOME": str(tmp_path)})
        backend.enable(["/opt/My Apps/python", "-m", "sigil", "serve"])
        content = backend.path.read_text()
        assert backend.path == tmp_path / "autostart" / "sigil.desktop"
        assert 'Exec="/opt/My Apps/python" -m sigil serve' in content
        assert backend.is_enabled()
        backend.disable()
        assert not backend.is_enabled()
        assert "was not enabled" in backend.disable()

    def test_windows_run_key(self) -> None:
        registry = FakeWinreg()
        backend = WindowsRunKeyAutostart(winreg_module=registry)
        assert not backend.is_enabled()
        backend.enable([r"C:\Program Files\Sigil\sigil.exe"])
        assert registry.values["Sigil"] == r'"C:\Program Files\Sigil\sigil.exe"'
        assert backend.is_enabled()
        backend.disable()
        assert not backend.is_enabled()
        assert "was not enabled" in backend.disable()

    @pytest.mark.parametrize(
        ("arg", "quoted"),
        [("serve", "serve"), ("/a b/c", '"/a b/c"'), ("$HOME", '"\\$HOME"'), ("", '""')],
    )
    def test_desktop_exec_quoting(self, arg: str, quoted: str) -> None:
        assert _desktop_exec_quote(arg) == quoted

    def test_launch_command(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert launch_command()[1:] == ["-m", "sigil", "serve"]
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        assert launch_command() == [sys.executable]

    def test_backend_per_os(self) -> None:
        assert isinstance(autostart_backend("Darwin"), MacLaunchAgentAutostart)
        assert isinstance(autostart_backend("Linux"), XdgAutostart)


# --------------------------------------------------------------------------- tray


class FakeMenuItem:
    def __init__(self, text: Any, action: Any, **kwargs: Any) -> None:
        self.text, self.action, self.kwargs = text, action, kwargs


class FakeMenu:
    SEPARATOR = object()

    def __init__(self, *items: Any) -> None:
        self.items = items


class FakeIcon:
    def __init__(self, name: str, icon: Any, title: str, menu: FakeMenu) -> None:
        self.name, self.icon, self.title, self.menu = name, icon, title, menu
        self.stopped = False
        self.menu_updates = 0

    def run(self) -> None:
        pass

    def stop(self) -> None:
        self.stopped = True

    def update_menu(self) -> None:
        self.menu_updates += 1


FAKE_PYSTRAY = SimpleNamespace(Icon=FakeIcon, Menu=FakeMenu, MenuItem=FakeMenuItem)


class FakeServer:
    def __init__(self) -> None:
        self.events: list[str] = []

    def start_background(self) -> None:
        self.events.append("start")

    def stop(self) -> None:
        self.events.append("stop")


class FakeAutostart:
    def __init__(self) -> None:
        self.enabled = False

    def is_enabled(self) -> bool:
        return self.enabled

    def enable(self, command: Any) -> str:
        self.enabled = True
        return "enabled"

    def disable(self) -> str:
        self.enabled = False
        return "disabled"


def make_tray(gateway: FakeGateway, tmp_path: Path) -> tuple[TrayApp, FakeServer, list[Any]]:
    opened: list[Any] = []
    server = FakeServer()
    tray = TrayApp(
        server,  # type: ignore[arg-type]
        TokenService(gateway),
        AgentSettings(),
        FakeAutostart(),
        tmp_path,
        pystray_module=FAKE_PYSTRAY,
        open_url=opened.append,
        open_dir=opened.append,
    )
    return tray, server, opened


class TestTray:
    def test_state_reflects_driver_and_tokens(self) -> None:
        gateway = FakeGateway()
        assert describe_state(TokenService(gateway)) == (
            TrayState.READY,
            "Token ready: Token TOKEN1",
        )
        gateway.tokens = []
        assert describe_state(TokenService(gateway))[0] is TrayState.NO_TOKEN
        gateway.driver = DriverStatus(loaded=False, error="no driver")
        assert describe_state(TokenService(gateway)) == (TrayState.ERROR, "no driver")

    def test_run_starts_and_stops_the_server(self, tmp_path: Path) -> None:
        tray, server, _ = make_tray(FakeGateway(), tmp_path)
        assert tray.run() == 0
        assert server.events == ["start", "stop"]

    def test_refresh_updates_icon_and_survives_busy_token(self, tmp_path: Path) -> None:
        gateway = FakeGateway()
        tray, _, _ = make_tray(gateway, tmp_path)
        tray._icon = FakeIcon("x", None, "", FakeMenu())
        tray.refresh()
        assert tray._icon.title == "Sigil — Token ready: Token TOKEN1"
        gateway.list_error = TokenBusyError("busy")
        tray.refresh()
        assert tray._state is TrayState.READY  # unchanged while a signature runs
        gateway.list_error = DriverNotFoundError("gone")
        tray.refresh()
        assert tray._state is TrayState.ERROR
        assert tray._icon.menu_updates == 2

    def test_menu_actions(self, tmp_path: Path) -> None:
        tray, _, opened = make_tray(FakeGateway(), tmp_path)
        tray._icon = FakeIcon("x", None, "", FakeMenu())
        items = {
            i.text: i
            for i in tray.build_menu().items
            if isinstance(i, FakeMenuItem) and isinstance(i.text, str)
        }
        items["Open API docs"].action()
        items["Open logs folder"].action()
        assert opened == ["http://127.0.0.1:8765/docs", tmp_path]
        toggle = items["Start at login"]
        assert toggle.kwargs["checked"](None) is False
        toggle.action()
        assert toggle.kwargs["checked"](None) is True
        toggle.action()
        assert toggle.kwargs["checked"](None) is False
        items["Quit"].action()
        assert tray._icon.stopped

    def test_icon_image(self) -> None:
        image = make_icon_image(TrayState.READY, size=32)
        assert image.size == (32, 32)
        assert image.getpixel((16, 2))[:3] == (0x2E, 0x7D, 0x32)

    def test_tray_needs_a_display_on_linux(self) -> None:
        assert tray_support("Linux", {}) == (
            False,
            "no graphical session (DISPLAY/WAYLAND_DISPLAY unset)",
        )

    def test_tray_available_when_extras_import(self) -> None:
        try:
            import pystray  # noqa: F401, PLC0415 - headless CI may not be able to load a backend
        except Exception as exc:
            pytest.skip(f"pystray unavailable here: {exc}")
        assert tray_support("Darwin", {}) == (True, "")


# --------------------------------------------------------------------------- server


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class TestServer:
    def test_probe_free_port(self) -> None:
        assert probe_port(AgentSettings(port=free_port())) is PortState.FREE

    def test_probe_detects_other_program(self) -> None:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]

            def answer_garbage() -> None:
                conn, _ = listener.accept()
                conn.sendall(b"SSH-2.0-OpenSSH\r\n")
                conn.close()

            threading.Thread(target=answer_garbage, daemon=True).start()
            assert probe_port(AgentSettings(port=port)) is PortState.OTHER_PROGRAM

    def test_background_server_is_detected_as_this_agent(self) -> None:
        settings = AgentSettings(port=free_port(), allowed_origins=("https://erp.example.com",))
        app = Harness().client.app
        server = AgentServer(app, settings)  # type: ignore[arg-type]
        server.start_background()
        try:
            assert server.started
            assert probe_port(settings) is PortState.THIS_AGENT
        finally:
            server.stop()
        assert probe_port(settings) is PortState.FREE


# --------------------------------------------------------------------------- CLI


@pytest.fixture
def isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point config, logs and the driver at a temp dir so tests never touch the real system."""
    monkeypatch.setenv("SIGIL_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("SIGIL_LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("SIGIL_PKCS11_MODULE", str(tmp_path / "missing-driver.so"))
    return tmp_path


class TestCli:
    def test_version(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert cli.main(["version"]) == 0
        assert capsys.readouterr().out.strip() == f"sigil {display_version()}"

    def test_config_init_path_and_show(
        self, isolated_env: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert cli.main(["config", "path"]) == 0
        assert capsys.readouterr().out.strip() == str(isolated_env / "config.toml")
        assert cli.main(["config", "init"]) == 0
        assert (isolated_env / "config.toml").is_file()
        assert cli.main(["config", "init"]) == 1  # refuses to overwrite
        assert cli.main(["config", "init", "--force"]) == 0
        capsys.readouterr()
        assert cli.main(["config", "show"]) == 0
        assert json.loads(capsys.readouterr().out)["port"] == 8765

    def test_invalid_config_exits_2(
        self, isolated_env: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (isolated_env / "config.toml").write_text("port = -1\n")
        assert cli.main(["diagnose"]) == 2
        assert "Invalid configuration" in capsys.readouterr().err

    def test_diagnose_without_driver(
        self, isolated_env: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert cli.main(["diagnose"]) == 3
        out = capsys.readouterr().out
        assert "NOT AVAILABLE  [DRIVER_NOT_FOUND]" in out
        assert "missing-driver.so" in out
        assert cli.main(["diagnose", "--json"]) == 3
        report = json.loads(capsys.readouterr().out)
        assert report["driver"]["loaded"] is False

    def test_diagnose_report_with_tokens(self, capsys: pytest.CaptureFixture[str]) -> None:
        gateway = FakeGateway(tokens=[token_info("SER1")])
        container = SimpleNamespace(token_service=TokenService(gateway))
        report = {
            "agent": {"version": "1", "codename": "Apricot", "python": "3"},
            "os": {"system": "Darwin", "release": "25", "machine": "arm64"},
            "config_file": {"path": "/c", "exists": True},
            "log_dir": "/l",
            "base_url": "http://127.0.0.1:8765",
            "allowed_origins": [],
            "tsa_url": None,
            "driver": {
                "loaded": True,
                "module_path": "/x.so",
                "manufacturer": "F",
                "library_version": "1.0",
            },
            "tokens": cli._token_report(container),
        }
        text = cli._render_report(report)
        assert "serial=SER1" in text
        assert "[USER] id=01" in text

    def test_autostart_status(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        backend = FakeAutostart()
        monkeypatch.setattr(cli, "autostart_backend", lambda: backend)
        assert cli.main(["autostart", "status"]) == 0
        assert cli.main(["autostart", "enable"]) == 0
        assert backend.enabled
        assert cli.main(["autostart", "disable"]) == 0
        assert capsys.readouterr().out.split() == ["disabled", "enabled", "disabled"]

    @pytest.mark.parametrize(
        ("state", "code"), [(PortState.THIS_AGENT, 0), (PortState.OTHER_PROGRAM, 1)]
    )
    def test_serve_respects_existing_instances(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch, state: PortState, code: int
    ) -> None:
        monkeypatch.setattr(cli, "probe_port", lambda _settings: state)
        assert cli.main(["serve", "--no-tray"]) == code

    def test_serve_headless_and_with_tray(
        self, isolated_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[str] = []
        monkeypatch.setattr(cli, "probe_port", lambda _settings: PortState.FREE)
        monkeypatch.setattr(cli.AgentServer, "run", lambda self: calls.append("headless"))
        assert cli.main(["serve", "--no-tray", "--port", "9999"]) == 0
        monkeypatch.setattr(cli, "tray_support", lambda: (True, ""))

        class FakeTrayApp:
            """Stands in for TrayApp entirely: the real constructor imports pystray, which
            fails on headless Linux CI (no X display)."""

            def __init__(self, *args: Any, **kwargs: Any) -> None:
                pass

            def run(self) -> int:
                calls.append("tray")
                return 0

        monkeypatch.setattr(cli, "TrayApp", FakeTrayApp)
        monkeypatch.setattr(cli, "autostart_backend", FakeAutostart)
        assert cli.main([]) == 0  # no command = serve with tray
        monkeypatch.setattr(cli, "tray_support", lambda: (False, "no display"))
        assert cli.main(["serve"]) == 0
        assert calls == ["headless", "tray", "headless"]
        assert (isolated_env / "logs" / "agent.log").is_file()

    def test_autostart_module_exports_backends(self) -> None:
        assert autostart_module.APP_LABEL == "com.sigil.agent"

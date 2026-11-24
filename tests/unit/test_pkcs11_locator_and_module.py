"""Driver discovery (all OSes, fake file system) and the single-instance module lifecycle."""

from __future__ import annotations

import threading
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

from sigil.domain.errors import DriverLoadError, DriverNotFoundError, TokenBusyError
from sigil.infrastructure.pkcs11.locator import ModuleLocator
from sigil.infrastructure.pkcs11.module import Pkcs11Module


class FakeFs:
    def __init__(
        self, files: Iterable[str] = (), globs: dict[tuple[str, str], list[str]] | None = None
    ):
        self.files = set(files)
        self.globs = globs or {}

    def is_file(self, path: str) -> bool:
        return path in self.files

    def glob(self, directory: str, pattern: str) -> Iterable[str]:
        return self.globs.get((directory, pattern), [])


class TestModuleLocator:
    def test_macos_vendor_driver_before_opensc(self) -> None:
        fs = FakeFs(
            {"/Library/OpenSC/lib/opensc-pkcs11.so", "/usr/local/lib/libcastle_v2.1.0.0.dylib"}
        )
        locator = ModuleLocator(system="Darwin", fs=fs)
        assert locator.candidates() == [
            "/usr/local/lib/libcastle_v2.1.0.0.dylib",
            "/Library/OpenSC/lib/opensc-pkcs11.so",
        ]

    def test_windows_expands_system_root_and_finds_versioned_dlls(self) -> None:
        sys32 = r"D:\Win\System32"
        fs = FakeFs(
            {sys32 + r"\eps2003csp11.dll", sys32 + r"\eps2003csp11v3.dll"},
            globs={
                (sys32, "eps2003*.dll"): [
                    sys32 + r"\eps2003csp11.dll",
                    sys32 + r"\eps2003csp11v3.dll",
                ]
            },
        )
        locator = ModuleLocator(system="Windows", env={"SystemRoot": r"D:\Win"}, fs=fs)
        assert locator.candidates() == [
            sys32 + r"\eps2003csp11.dll",
            sys32 + r"\eps2003csp11v3.dll",
        ]
        assert any(
            p.startswith(r"C:\Program Files")
            for p in ModuleLocator(system="Windows", env={}, fs=fs).searched_locations()
        )

    def test_linux_extra_paths_come_first(self) -> None:
        custom = str(Path("/opt/custom/p11.so"))  # host-native spelling of a Path
        fs = FakeFs({custom, "/usr/lib/opensc-pkcs11.so"})
        locator = ModuleLocator(system="Linux", extra=[Path(custom)], fs=fs)
        assert locator.candidates() == [custom, "/usr/lib/opensc-pkcs11.so"]

    def test_explicit_module_disables_auto_detection(self) -> None:
        castle = str(Path("/usr/local/lib/libcastle_v2.1.0.0.dylib"))  # host-native spelling
        fs = FakeFs({castle})
        missing = ModuleLocator(system="Darwin", explicit=Path("/nope.so"), fs=fs)
        assert missing.candidates() == []
        assert missing.searched_locations() == [str(Path("/nope.so"))]
        present = ModuleLocator(system="Darwin", explicit=Path(castle), fs=fs)
        assert present.candidates() == [castle]

    def test_duplicates_are_removed_and_unknown_os_is_empty(self) -> None:
        path = "/usr/local/lib/libcastle_v2.1.0.0.dylib"
        fs = FakeFs({path}, globs={("/usr/local/lib", "libcastle*.dylib"): [path]})
        assert ModuleLocator(system="Darwin", fs=fs).candidates() == [path]
        assert ModuleLocator(system="Plan9", fs=fs).candidates() == []


class FakeLib:
    def __init__(self, path: str) -> None:
        self.path = path
        self.manufacturer_id = "Feitian Technologies"
        self.library_description = "Fake PKCS#11"
        self.library_version = (1, 20)
        self.reinitialized = 0
        self.fail_reinit = False

    def reinitialize(self) -> None:
        if self.fail_reinit:
            raise RuntimeError("driver wedged")
        self.reinitialized += 1


class CountingLoader:
    def __init__(self, failing: set[str] | None = None) -> None:
        self.calls: list[str] = []
        self.failing = failing or set()

    def __call__(self, path: str) -> Any:
        self.calls.append(path)
        if path in self.failing:
            raise OSError(f"dlopen({path}): incompatible architecture")
        return FakeLib(path)


def make_module(
    files: Iterable[str], loader: CountingLoader, timeout: float = 5.0
) -> tuple[Pkcs11Module, FakeFs]:
    fs = FakeFs(files)
    return Pkcs11Module(
        ModuleLocator(system="Linux", fs=fs), lock_timeout=timeout, loader=loader
    ), fs


class TestPkcs11Module:
    def test_library_is_loaded_exactly_once(self) -> None:
        """The driver is located and loaded once, then reused by every request."""
        loader = CountingLoader()
        module, _ = make_module(["/usr/lib/opensc-pkcs11.so"], loader)
        libs = []
        for _ in range(10):
            with module.exclusive() as lib:
                libs.append(lib)
        assert loader.calls == ["/usr/lib/opensc-pkcs11.so"]
        assert all(lib is libs[0] for lib in libs)

    def test_falls_back_to_the_next_loadable_candidate(self) -> None:
        loader = CountingLoader(failing={"/usr/lib/libcastle.so.1.0.0"})
        module, _ = make_module(
            ["/usr/lib/libcastle.so.1.0.0", "/usr/lib/opensc-pkcs11.so"], loader
        )
        with module.exclusive() as lib:
            assert lib.path == "/usr/lib/opensc-pkcs11.so"
        assert module.status().module_path == "/usr/lib/opensc-pkcs11.so"

    def test_no_driver(self) -> None:
        module, _ = make_module([], CountingLoader())
        with pytest.raises(DriverNotFoundError) as exc, module.exclusive():
            pass
        assert "/usr/lib/opensc-pkcs11.so" in exc.value.details["searched"]  # type: ignore[operator]
        status = module.status()
        assert not status.loaded
        assert status.error_code == "DRIVER_NOT_FOUND"

    def test_driver_present_but_unloadable(self) -> None:
        path = "/usr/lib/opensc-pkcs11.so"
        module, _ = make_module([path], CountingLoader(failing={path}))
        with pytest.raises(DriverLoadError, match="architecture") as exc, module.exclusive():
            pass
        assert "incompatible architecture" in exc.value.details["errors"][path]  # type: ignore[index]

    def test_driver_installed_while_running_is_picked_up(self) -> None:
        loader = CountingLoader()
        module, fs = make_module([], loader)
        assert not module.status().loaded
        fs.files.add("/usr/lib/opensc-pkcs11.so")
        status = module.status()
        assert status.loaded
        assert status.manufacturer == "Feitian Technologies"
        assert status.library_version == "1.20"

    def test_busy_token_times_out_with_token_busy(self) -> None:
        module, _ = make_module(["/usr/lib/opensc-pkcs11.so"], CountingLoader(), timeout=0.05)
        holding, release = threading.Event(), threading.Event()

        def hold() -> None:
            with module.exclusive():
                holding.set()
                release.wait(5)

        worker = threading.Thread(target=hold)
        worker.start()
        holding.wait(5)
        try:
            with pytest.raises(TokenBusyError), module.exclusive():
                pass
            assert module.status().loaded  # health still answers while busy
        finally:
            release.set()
            worker.join()

    def test_invalidate_reinitializes_or_drops_the_driver(self) -> None:
        loader = CountingLoader()
        module, _ = make_module(["/usr/lib/opensc-pkcs11.so"], loader)
        with module.exclusive() as lib:
            pass
        module.invalidate()
        assert lib.reinitialized == 1
        lib.fail_reinit = True
        module.invalidate()
        with module.exclusive() as reloaded:
            assert reloaded is not lib
        assert len(loader.calls) == 2

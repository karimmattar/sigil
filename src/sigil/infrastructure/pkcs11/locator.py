"""Find PKCS#11 modules (token "drivers") on Windows, macOS and Linux.

The catalog is data, not code: supporting another token vendor or OS means adding an
entry to :data:`DRIVER_CATALOG` (Open/Closed principle). Vendor drivers are listed
before the generic OpenSC module so the vendor's own driver wins when both exist.

Windows paths may contain ``{SystemRoot}`` / ``{ProgramFiles}`` placeholders that are
expanded from the environment. A 32-bit Python on 64-bit Windows transparently gets
``SysWOW64`` when it opens ``System32`` (WOW64 redirection), so bitness is handled by
the OS — the Python and the driver just have to match, which the loader reports.
"""

from __future__ import annotations

import os
import platform
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Protocol


@dataclass(frozen=True)
class PlatformDrivers:
    """Known driver locations for one operating system, in priority order."""

    vendor_paths: tuple[str, ...] = ()
    #: ``(directory, glob pattern)`` pairs for vendor drivers with versioned file names.
    vendor_globs: tuple[tuple[str, str], ...] = ()
    #: Generic modules (OpenSC) tried last.
    generic_paths: tuple[str, ...] = field(default=())


_SYS32 = "{SystemRoot}\\System32"

DRIVER_CATALOG: Mapping[str, PlatformDrivers] = MappingProxyType(
    {
        "Windows": PlatformDrivers(
            vendor_paths=(
                _SYS32 + "\\eps2003csp11v2.dll",  # Feitian ePass2003 v2 (Egypt Trust / DeltaTrust)
                _SYS32 + "\\eps2003csp11.dll",  # Feitian ePass2003 (Egypt Trust / DeltaTrust)
                _SYS32 + "\\SignatureP11.dll",  # newer Egypt Trust tokens
                _SYS32 + "\\HYP2003_PKCS11.dll",  # Hypersecu HYP2003
                _SYS32 + "\\ShuttleCsp11_3003.dll",  # Feitian ePass3003
                _SYS32 + "\\eTPKCS11.dll",  # SafeNet / Thales eToken
                _SYS32 + "\\IDPrimePKCS11.dll",  # Thales IDPrime
                _SYS32 + "\\wdpkcs.dll",  # WatchData
            ),
            vendor_globs=(
                (_SYS32, "eps2003*.dll"),
                (_SYS32, "*castle*.dll"),
                (_SYS32, "*hyp*pkcs11*.dll"),
            ),
            generic_paths=("{ProgramFiles}\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll",),
        ),
        "Darwin": PlatformDrivers(
            vendor_paths=(
                # Feitian ePass2003 (Egypt Trust / DeltaTrust)
                "/usr/local/lib/libcastle_v2.1.0.0.dylib",
                "/usr/local/lib/libcastle.1.0.0.dylib",
                "/usr/local/lib/libeTPkcs11.dylib",  # SafeNet / Thales eToken
                "/Library/Frameworks/eToken.framework/Versions/Current/libeToken.dylib",
                "/usr/local/lib/libIDPrimePKCS11.dylib",  # Thales IDPrime
            ),
            vendor_globs=(("/usr/local/lib", "libcastle*.dylib"),),
            generic_paths=(
                "/Library/OpenSC/lib/opensc-pkcs11.so",
                "/opt/homebrew/lib/opensc-pkcs11.so",
                "/usr/local/lib/opensc-pkcs11.so",
            ),
        ),
        "Linux": PlatformDrivers(
            vendor_paths=(
                "/usr/lib/libcastle.so.1.0.0",  # Feitian ePass2003 (Egypt Trust / DeltaTrust)
                "/usr/local/lib/libcastle.so.1.0.0",
                "/usr/lib/libeTPkcs11.so",  # SafeNet / Thales eToken
                "/usr/lib/libIDPrimePKCS11.so",  # Thales IDPrime
            ),
            vendor_globs=(("/usr/lib", "libcastle*.so*"), ("/usr/local/lib", "libcastle*.so*")),
            generic_paths=(
                "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
                "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so",
                "/usr/lib64/opensc-pkcs11.so",
                "/usr/lib/opensc-pkcs11.so",
            ),
        ),
    }
)

_WINDOWS_DEFAULTS = {"SystemRoot": "C:\\Windows", "ProgramFiles": "C:\\Program Files"}


class FileSystem(Protocol):
    """The two file-system queries the locator needs (faked in tests)."""

    def is_file(self, path: str) -> bool: ...

    def glob(self, directory: str, pattern: str) -> Iterable[str]: ...


class LocalFileSystem:
    """Real file system."""

    def is_file(self, path: str) -> bool:
        return Path(path).is_file()

    def glob(self, directory: str, pattern: str) -> Iterable[str]:
        base = Path(directory)
        return sorted(str(p) for p in base.glob(pattern)) if base.is_dir() else []


class ModuleLocator:
    """Produces the ordered list of existing PKCS#11 module files to try."""

    def __init__(
        self,
        *,
        explicit: Path | None = None,
        extra: Sequence[Path] = (),
        system: str | None = None,
        env: Mapping[str, str] | None = None,
        catalog: Mapping[str, PlatformDrivers] = DRIVER_CATALOG,
        fs: FileSystem | None = None,
    ) -> None:
        self._explicit = explicit
        self._extra = tuple(extra)
        self._system = system or platform.system()
        self._env = os.environ if env is None else env
        self._catalog = catalog
        self._fs = fs or LocalFileSystem()

    @property
    def explicit(self) -> Path | None:
        """Module path forced by configuration (no auto-detection when set)."""
        return self._explicit

    def searched_locations(self) -> list[str]:
        """Every location considered (existing or not) — shown by ``diagnose``/health."""
        if self._explicit is not None:
            return [str(self._explicit)]
        drivers = self._catalog.get(self._system, PlatformDrivers())
        sep = "\\" if self._system == "Windows" else "/"
        globs = [f"{self._expand(d)}{sep}{p}" for d, p in drivers.vendor_globs]
        return [
            *(str(p) for p in self._extra),
            *(self._expand(p) for p in drivers.vendor_paths),
            *globs,
            *(self._expand(p) for p in drivers.generic_paths),
        ]

    def candidates(self) -> list[str]:
        """Existing module files in priority order, without duplicates.

        When a module is configured explicitly, auto-detection is disabled: a missing
        explicit module yields an empty list (reported as "driver not found") rather than
        silently falling back to some other driver.
        """
        if self._explicit is not None:
            return [str(self._explicit)] if self._fs.is_file(str(self._explicit)) else []
        drivers = self._catalog.get(self._system, PlatformDrivers())
        ordered: list[str] = [str(p) for p in self._extra]
        ordered += [self._expand(p) for p in drivers.vendor_paths]
        for directory, pattern in drivers.vendor_globs:
            ordered += self._fs.glob(self._expand(directory), pattern)
        ordered += [self._expand(p) for p in drivers.generic_paths]
        return [p for p in dict.fromkeys(ordered) if self._fs.is_file(p)]

    def _expand(self, template: str) -> str:
        values = {key: self._env.get(key, default) for key, default in _WINDOWS_DEFAULTS.items()}
        return template.format(**values)

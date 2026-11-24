"""Find PKCS#11 modules (token "drivers") on Windows, macOS and Linux.

The catalog is data, not code: supporting another token vendor or OS means adding an
entry to :data:`DRIVER_CATALOG` (Open/Closed principle). Vendor drivers are listed
before the generic OpenSC module so the vendor's own driver wins when both exist.

Windows paths may contain ``{SystemRoot}``, ``{ProgramFiles}`` and ``{ProgramFilesX86}``
placeholders that are expanded from the environment. A 32-bit Python on 64-bit Windows
transparently gets ``SysWOW64`` when it opens ``System32`` (WOW64 redirection), so bitness
is handled by the OS — the Python and the driver just have to match, which the loader
reports.

Every entry carries an evidence tag (research of 2026-11-24):

* ``[verified]``   — seen in the vendor's own package or installed files;
* ``[documented]`` — stated by vendor/integrator documentation or several independent guides;
* ``[convention]`` — standard install location of the platform's package manager.

Entries without evidence are deliberately left out; any other module can still be used
by setting ``pkcs11_module`` (or ``extra_module_paths``) in the configuration.
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

# Egyptian e-signature providers ship these token families (provider download pages):
#   Egypt Trust  -> Feitian HyperPKI HYP2003 / ePass2003, WatchData ProxKey
#   Fixed Misr   -> Feitian ePass2003 Auto
#   MCDR         -> Feitian ePass2003
#   El-Delta     -> not published (ships its own activation tool)
DRIVER_CATALOG: Mapping[str, PlatformDrivers] = MappingProxyType(
    {
        "Windows": PlatformDrivers(
            vendor_paths=(
                # Feitian HyperPKI HYP2003 [documented: NIC guide; HyperPKI_HYP2003_Setup report]
                _SYS32 + "\\eps2003csp11v2.dll",
                # Feitian ePass2003 [documented: Xolphin/Adobe guide; Egypt e-invoice signers]
                _SYS32 + "\\eps2003csp11.dll",
                # WatchData ProxKey [verified: Egypt Trust WatchData installer; NIC guide]
                _SYS32 + "\\SignatureP11.dll",
                # SafeNet / Thales eToken (SafeNet Authentication Client) [documented]
                _SYS32 + "\\eTPKCS11.dll",
                # Thales IDPrime via SafeNet Authentication Client 10.8+ [documented: Nexus]
                "{ProgramFiles}\\SafeNet\\Authentication\\SAC\\x64\\IDPrimePKCS1164.dll",
                "{ProgramFiles}\\SafeNet\\Authentication\\SAC\\x32\\IDPrimePKCS11.dll",
                # Thales/Gemalto IDPrime via IDGo 800 [documented: Nexus]
                "{ProgramFilesX86}\\Gemalto\\IDGo 800 PKCS#11\\IDPrimePKCS1164.dll",
                "{ProgramFilesX86}\\Gemalto\\IDGo 800 PKCS#11\\IDPrimePKCS11.dll",
                # Other common tokens [documented: NIC DSC guide]
                _SYS32 + "\\TRUSTKEYP11_ND_v34.dll",  # TrustKey
                _SYS32 + "\\CryptoIDA_pkcs11.dll",  # mToken CryptoID
            ),
            # Feitian has shipped several versioned names (eps2003csp11.dll, ...v2.dll).
            vendor_globs=((_SYS32, "eps2003csp11*.dll"),),
            # OpenSC [documented: OpenSC project]; it does not support the HYP2003 token.
            generic_paths=("{ProgramFiles}\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll",),
        ),
        "Darwin": PlatformDrivers(
            vendor_paths=(
                # Feitian HyperPKI HYP2003 [verified: installed by HyperPKI package]
                "/usr/local/lib/libcastle_v2.1.0.0.dylib",
                # Feitian ePass2003 [verified: Egypt Trust "ePass2003-Castle-mac" package]
                "/usr/local/lib/libcastle.1.0.0.dylib",
                # WatchData ProxKey [documented: CryptoPlanet guide; ZySign]
                "/usr/local/lib/wdProxKeyUsbKeyTool/libwdpkcs_Proxkey.dylib",
                "/usr/local/lib/libwdpkcs.dylib",
                # SafeNet eToken [documented: DigiCert KB; symlink into eToken.framework]
                "/usr/local/lib/libeTPkcs11.dylib",
                "/Library/Frameworks/eToken.framework/Versions/Current/libeToken.dylib",
            ),
            vendor_globs=(("/usr/local/lib", "libcastle*.dylib"),),
            generic_paths=(
                "/Library/OpenSC/lib/opensc-pkcs11.so",  # OpenSC installer [documented]
                "/opt/homebrew/lib/opensc-pkcs11.so",  # Homebrew, Apple silicon [convention]
                "/usr/local/lib/opensc-pkcs11.so",  # Homebrew, Intel [convention]
            ),
        ),
        "Linux": PlatformDrivers(
            vendor_paths=(
                # Feitian ePass2003: "copy anywhere" library; the vendor's own registration
                # script uses /usr/local/lib [verified: Egypt Trust "ePass2003-Linux" package]
                "/usr/local/lib/libcastle.so.1.0.0",
                "/usr/lib/libcastle.so.1.0.0",
                # WatchData ProxKey [verified: Egypt Trust proxkey .deb/.rpm install script]
                "/usr/lib/WatchData/ProxKey/lib/libwdpkcs_SignatureP11.so",
                # SafeNet eToken (SafeNet Authentication Client) [documented]
                "/usr/lib/libeTPkcs11.so",
                "/usr/local/lib/libeTPkcs11.so",
            ),
            # Feitian HyperPKI HYP2003 ships libcastle_v2.so.1.0.0 [documented] — no installer,
            # so match any libcastle* placed in the usual library directories.
            vendor_globs=(("/usr/local/lib", "libcastle*.so*"), ("/usr/lib", "libcastle*.so*")),
            generic_paths=(
                "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",  # Debian/Ubuntu [verified]
                "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so",  # Debian/Ubuntu arm64 [verified]
                "/usr/lib64/opensc-pkcs11.so",  # Fedora/RHEL/openSUSE [convention]
                "/usr/lib/opensc-pkcs11.so",  # Arch [convention]
            ),
        ),
    }
)

_WINDOWS_DEFAULTS = {
    "SystemRoot": ("SystemRoot", "C:\\Windows"),
    "ProgramFiles": ("ProgramFiles", "C:\\Program Files"),
    "ProgramFilesX86": ("ProgramFiles(x86)", "C:\\Program Files (x86)"),
}


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
        values = {
            placeholder: self._env.get(variable, default)
            for placeholder, (variable, default) in _WINDOWS_DEFAULTS.items()
        }
        return template.format(**values)

# PyInstaller build definition for the Sigil desktop app.
#
#   Windows : dist/sigil.exe            (one file, no console window)
#   macOS   : dist/Sigil.app            (menu-bar app, no Dock icon)
#   Linux   : dist/sigil                (one file)
#
# Build on each target OS (PyInstaller does not cross-compile):
#   python -m PyInstaller --noconfirm --clean packaging/sigil.spec
# The token driver (PKCS#11 module) is NOT bundled: it is installed by the token vendor
# and must match the agent's architecture (64-bit x86 / ARM64).

import re
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH).parent
VERSION = re.search(
    r'__version__ = "([^"]+)"', (ROOT / "src" / "sigil" / "__init__.py").read_text()
).group(1)
APP = "sigil"

if sys.platform == "win32":
    tray_backends = ["pystray._win32"]
elif sys.platform == "darwin":
    tray_backends = ["pystray._darwin"]
else:
    tray_backends = ["pystray._appindicator", "pystray._gtk", "pystray._xorg"]

hiddenimports = [
    *collect_submodules("uvicorn"),  # uvicorn picks loops/protocols dynamically
    *collect_submodules("pyhanko"),  # pyHanko imports signing/stamp helpers lazily
    *collect_submodules("pyhanko_certvalidator"),
    *collect_submodules("sigil"),
    "pkcs11._pkcs11",
    "pkcs11.util.rsa",
    "pkcs11.util.x509",
    "pkcs11.util.ec",
    *tray_backends,
]
datas = [*collect_data_files("pyhanko"), *collect_data_files("pyhanko_certvalidator")]

a = Analysis(
    [str(ROOT / "packaging" / "launcher.py")],
    pathex=[str(ROOT / "src")],
    hiddenimports=hiddenimports,
    datas=datas,
    excludes=["tkinter", "pytest", "mypy", "ruff", "IPython"],
    noarchive=False,
)
pyz = PYZ(a.pure)

if sys.platform == "darwin":
    exe = EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name=APP,
        console=False,
        target_arch=None,  # build on the architecture you ship (arm64 or x86_64)
    )
    coll = COLLECT(exe, a.binaries, a.datas, name=APP)
    app = BUNDLE(
        coll,
        name="Sigil.app",
        bundle_identifier="com.sigil.agent",
        version=VERSION,
        info_plist={
            "LSUIElement": True,  # menu-bar only, no Dock icon
            "CFBundleShortVersionString": VERSION,
            "NSHumanReadableCopyright": "Sigil",
        },
    )
else:
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name=APP,
        console=sys.platform != "win32",  # Windows: no console window at login
        upx=False,
    )

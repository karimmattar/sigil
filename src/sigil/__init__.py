"""Sigil — your token's seal, one click from the browser.

A small local desktop service that lets a browser-based web system use a PKCS#11
hardware token (Egypt Trust / DeltaTrust ePass2003, SafeNet eToken, OpenSC-supported
cards, …) for PDF (PAdES) and CMS/CAdES signing.

Layers (dependencies point inwards only)::

    desktop / api  ──►  application  ──►  domain  ◄──  infrastructure

See ``docs/ARCHITECTURE.md`` for the full picture.
"""

__all__ = ["CODENAMES", "SERVICE_NAME", "__codename__", "__version__", "display_version"]

__version__ = "1.0.0"

#: Fruit codename of the current minor version — see docs/RELEASING.md.
__codename__ = "Apricot"

#: Codename sequence: every new minor version takes the next fruit, alphabetically.
CODENAMES = (
    "Apricot", "Banana", "Cherry", "Date", "Elderberry", "Fig", "Guava", "Honeydew",
    "Jackfruit", "Kiwi", "Lemon", "Mango", "Nectarine", "Olive", "Papaya", "Quince",
    "Raspberry", "Strawberry", "Tangerine", "Ugli", "Watermelon", "Yuzu",
)  # fmt: skip


def display_version() -> str:
    """Human-readable version, e.g. ``1.0.0 "Apricot"``."""
    return f'{__version__} "{__codename__}"'


#: Identifier reported by ``/api/v1/health``; also used to detect an already running instance.
SERVICE_NAME = "sigil"

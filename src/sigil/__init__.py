"""Sigil — your token's seal, one click from the browser.

A small local desktop service that lets a browser-based web system use a PKCS#11
hardware token (Egypt Trust / DeltaTrust ePass2003, SafeNet eToken, OpenSC-supported
cards, …) for PDF (PAdES) and CMS/CAdES signing.

Layers (dependencies point inwards only)::

    desktop / api  ──►  application  ──►  domain  ◄──  infrastructure

See ``docs/ARCHITECTURE.md`` for the full picture.
"""

__all__ = ["SERVICE_NAME", "__version__"]

__version__ = "1.0.0"

#: Identifier reported by ``/api/v1/health``; also used to detect an already running instance.
SERVICE_NAME = "sigil"

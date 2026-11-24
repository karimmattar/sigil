"""Logging configuration and the audit-log adapter.

* ``agent.log`` — operational log (rotating), also mirrored to stderr when there is one
  (a windowed PyInstaller build on Windows has no stderr).
* ``audit.log`` — one JSON line per signing attempt (:class:`LoggingAuditLog`).
  Contains the token serial, certificate id and a SHA-256 of the payload — never the PIN
  or the document.
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import asdict
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

from sigil.domain.models import AuditEvent

ROOT_LOGGER = "sigil"
AUDIT_LOGGER = "sigil.audit"
_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
_MAX_BYTES = 5 * 1024 * 1024
_BACKUPS = 5


def configure_logging(level: str, directory: Path | None) -> Path | None:
    """Configure the ``sigil`` and uvicorn loggers. Returns the log directory used."""
    formatter = logging.Formatter(_FORMAT)
    handlers: list[logging.Handler] = []
    if sys.stderr is not None:
        handlers.append(logging.StreamHandler(sys.stderr))

    used_dir: Path | None = None
    audit_handler: logging.Handler | None = None
    if directory is not None:
        try:
            directory.mkdir(parents=True, exist_ok=True)
            handlers.append(
                RotatingFileHandler(
                    directory / "agent.log",
                    maxBytes=_MAX_BYTES,
                    backupCount=_BACKUPS,
                    encoding="utf-8",
                )
            )
            audit_handler = RotatingFileHandler(
                directory / "audit.log", maxBytes=_MAX_BYTES, backupCount=_BACKUPS, encoding="utf-8"
            )
            audit_handler.setFormatter(logging.Formatter("%(message)s"))
            used_dir = directory
        except OSError as exc:  # read-only home, permissions… keep running with stderr only
            logging.getLogger(ROOT_LOGGER).warning("Cannot write logs to %s: %s", directory, exc)

    for name in (ROOT_LOGGER, "uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = False
        logger.setLevel(level)
        for handler in handlers:
            handler.setFormatter(formatter)
            logger.addHandler(handler)

    audit = logging.getLogger(AUDIT_LOGGER)
    audit.handlers.clear()
    audit.setLevel(logging.INFO)
    if audit_handler is not None:
        audit.addHandler(audit_handler)
    audit.propagate = True  # also show audit lines in the main log
    return used_dir


class LoggingAuditLog:
    """:class:`~sigil.domain.ports.AuditLog` adapter writing JSON lines."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or logging.getLogger(AUDIT_LOGGER)

    def record(self, event: AuditEvent) -> None:
        entry = {"time": datetime.now(UTC).isoformat(timespec="seconds"), **asdict(event)}
        self._logger.info(json.dumps(entry, ensure_ascii=False, sort_keys=True))

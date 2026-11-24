"""Run uvicorn for the agent (blocking, or in a background thread for the tray app)."""

from __future__ import annotations

import enum
import json
import logging
import socket
import ssl
import threading
import time
import urllib.request
from typing import Any

import uvicorn
from fastapi import FastAPI

from sigil import SERVICE_NAME
from sigil.infrastructure.config import AgentSettings

logger = logging.getLogger(__name__)


class PortState(enum.Enum):
    """Who (if anyone) owns the configured port."""

    FREE = "free"
    THIS_AGENT = "agent"
    OTHER_PROGRAM = "other"


def probe_port(settings: AgentSettings, timeout: float = 1.5) -> PortState:
    """Detect an already running agent so a second launch exits instead of failing to bind."""
    host = "127.0.0.1" if settings.host in ("0.0.0.0", "::") else settings.host  # noqa: S104
    try:
        with socket.create_connection((host, settings.port), timeout=timeout):
            pass
    except OSError:
        return PortState.FREE

    context = None
    if settings.uses_tls:
        # Probing our own loopback listener; its (often self-issued) certificate is irrelevant.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(  # noqa: S310 - fixed http(s) loopback URL
            f"{settings.base_url}/api/v1/health", timeout=timeout, context=context
        ) as response:
            payload: Any = json.loads(response.read())
    except (OSError, ValueError):
        return PortState.OTHER_PROGRAM
    return (
        PortState.THIS_AGENT if payload.get("service") == SERVICE_NAME else PortState.OTHER_PROGRAM
    )


class AgentServer:
    """Thin wrapper around :class:`uvicorn.Server` with start/stop for the tray."""

    STARTUP_TIMEOUT = 15.0

    def __init__(self, app: FastAPI, settings: AgentSettings) -> None:
        config = uvicorn.Config(
            app,
            host=settings.host,
            port=settings.port,
            log_config=None,  # keep our logging configuration
            server_header=False,
            proxy_headers=False,
            ssl_certfile=str(settings.ssl_certfile) if settings.ssl_certfile else None,
            ssl_keyfile=str(settings.ssl_keyfile) if settings.ssl_keyfile else None,
        )
        self._server = uvicorn.Server(config)
        self._thread: threading.Thread | None = None

    @property
    def started(self) -> bool:
        return bool(self._server.started)

    def run(self) -> None:
        """Serve in the current thread until interrupted (Ctrl+C / SIGTERM)."""
        self._server.run()

    def start_background(self) -> None:
        """Serve in a daemon thread and wait until the socket is listening."""
        self._thread = threading.Thread(target=self._server.run, name="uvicorn", daemon=True)
        self._thread.start()
        deadline = time.monotonic() + self.STARTUP_TIMEOUT
        while not self._server.started:
            if not self._thread.is_alive() or time.monotonic() > deadline:
                raise RuntimeError("The HTTP server failed to start; see the agent log.")
            time.sleep(0.05)

    def stop(self, timeout: float = 5.0) -> None:
        """Ask uvicorn to shut down gracefully and wait for the thread."""
        self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout)

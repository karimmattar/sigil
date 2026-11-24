"""Composition root: the only place that knows which concrete adapters implement each port.

Swapping an adapter (e.g. a different signing library or a fake for tests) only touches
this file — or pass the replacement in through the keyword arguments of
:func:`build_container`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pyhanko.sign.timestamps import TimeStamper

from sigil.application.signing_service import SigningService
from sigil.application.token_service import TokenService
from sigil.domain.ports import AuditLog, TokenGateway
from sigil.infrastructure.config import AgentSettings
from sigil.infrastructure.logging_setup import LoggingAuditLog
from sigil.infrastructure.pkcs11 import ModuleLocator, Pkcs11Module, Pkcs11TokenGateway
from sigil.infrastructure.pyhanko_engine import (
    PyHankoCmsEngine,
    PyHankoPdfEngine,
    TimestampProvider,
)


@dataclass(frozen=True)
class Container:
    """Everything the API and desktop layers need, fully wired."""

    settings: AgentSettings
    token_service: TokenService
    signing_service: SigningService
    timestamps_available: bool
    module_locator: ModuleLocator | None = None


def build_container(
    settings: AgentSettings,
    *,
    gateway: TokenGateway | None = None,
    module_loader: Callable[[str], Any] | None = None,
    timestamper_factory: Callable[[], TimeStamper] | None = None,
    audit_log: AuditLog | None = None,
) -> Container:
    """Wire the production object graph (keyword arguments exist for tests/integration)."""
    locator: ModuleLocator | None = None
    if gateway is None:
        locator = ModuleLocator(explicit=settings.pkcs11_module, extra=settings.extra_module_paths)
        module = Pkcs11Module(
            locator, lock_timeout=settings.token_lock_timeout_seconds, loader=module_loader
        )
        gateway = Pkcs11TokenGateway(module)

    timestamps = TimestampProvider(
        settings.tsa_url, timeout=settings.tsa_timeout_seconds, factory=timestamper_factory
    )
    signing_service = SigningService(
        gateway,
        PyHankoPdfEngine(timestamps, strict=settings.pdf_strict_parsing),
        PyHankoCmsEngine(timestamps),
        audit_log or LoggingAuditLog(),
    )
    return Container(
        settings=settings,
        token_service=TokenService(gateway),
        signing_service=signing_service,
        timestamps_available=timestamps.available,
        module_locator=locator,
    )

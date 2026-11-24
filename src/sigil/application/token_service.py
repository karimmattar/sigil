"""Read-only token use cases: driver health, token discovery and certificate listing."""

from __future__ import annotations

from sigil.domain.models import CertificateInfo, DriverStatus, TokenInfo
from sigil.domain.policies import resolve_token
from sigil.domain.ports import TokenGateway


class TokenService:
    """Answers "what is plugged in and what can it sign with?" — no PIN required."""

    def __init__(self, gateway: TokenGateway) -> None:
        self._gateway = gateway

    def driver_status(self) -> DriverStatus:
        """Driver (PKCS#11 module) load status; never raises."""
        return self._gateway.driver_status()

    def list_tokens(self) -> list[TokenInfo]:
        """All connected, initialised tokens."""
        return list(self._gateway.list_tokens())

    def list_certificates(self, token_serial: str | None = None) -> list[CertificateInfo]:
        """Certificates on the given token (or on the only connected token)."""
        token = resolve_token(self._gateway.list_tokens(), token_serial)
        return list(self._gateway.list_certificates(token.serial))

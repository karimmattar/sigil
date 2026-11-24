"""Ports: the interfaces the domain/application need from the outside world.

Infrastructure adapters implement these (python-pkcs11, pyHanko, logging). Keeping
them small and role-specific (Interface Segregation) means tests can provide tiny fakes
and a different driver stack could be plugged in without touching the use cases.
"""

from __future__ import annotations

from collections.abc import Sequence
from contextlib import AbstractContextManager
from typing import Protocol, runtime_checkable

from .models import (
    AuditEvent,
    CertificateInfo,
    CmsSignatureOptions,
    DriverStatus,
    PdfSignatureOptions,
    Pin,
    SignedPdf,
    TokenInfo,
)


@runtime_checkable
class KeyHandle(Protocol):
    """Opaque reference to a token private key, valid only while its session is open.

    The domain only needs to know which certificate it belongs to; signing engines
    know how to use the concrete adapter object.
    """

    @property
    def certificate(self) -> CertificateInfo: ...


class SigningSession(Protocol):
    """A logged-in session on one token."""

    def certificates(self) -> Sequence[CertificateInfo]:
        """Certificates on the token, with ``has_private_key`` resolved (logged-in view)."""
        ...

    def key_for(self, certificate: CertificateInfo) -> KeyHandle:
        """Return a handle to the private key that belongs to ``certificate``."""
        ...


class TokenGateway(Protocol):
    """Access to the token driver: discovery, read-only queries and authenticated sessions."""

    def driver_status(self) -> DriverStatus:
        """Locate/load the driver if needed and report the result. Never raises."""
        ...

    def list_tokens(self) -> Sequence[TokenInfo]:
        """Connected, initialised tokens."""
        ...

    def list_certificates(self, token_serial: str) -> Sequence[CertificateInfo]:
        """Certificates on a token, readable without a PIN."""
        ...

    def open_session(self, token_serial: str, pin: Pin) -> AbstractContextManager[SigningSession]:
        """Log in to a token for the duration of the ``with`` block (exclusive access)."""
        ...


class PdfSigningEngine(Protocol):
    """Produces a signed PDF using a token key."""

    def sign_pdf(
        self, key: KeyHandle, document: bytes, options: PdfSignatureOptions
    ) -> SignedPdf: ...


class CmsSigningEngine(Protocol):
    """Produces a DER-encoded CMS ``ContentInfo`` (SignedData) over arbitrary bytes."""

    def sign_data(self, key: KeyHandle, data: bytes, options: CmsSignatureOptions) -> bytes: ...


class AuditLog(Protocol):
    """Append-only audit trail of signing operations."""

    def record(self, event: AuditEvent) -> None: ...

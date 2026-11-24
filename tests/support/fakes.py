"""In-memory fakes of the domain ports (used by unit tests of services, API and tray)."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from pyhanko.sign.signers import Signer

from sigil.domain.errors import AgentError, TokenNotFoundError
from sigil.domain.models import (
    AuditEvent,
    CertificateInfo,
    CmsSignatureOptions,
    DriverStatus,
    KeyUsage,
    PdfSignatureOptions,
    Pin,
    SignedPdf,
    TokenInfo,
)

NOW = datetime(2026, 6, 1, tzinfo=UTC)


def cert_info(id_hex: str = "01", **overrides: Any) -> CertificateInfo:
    """A CertificateInfo with sensible defaults (no real crypto needed)."""
    values: dict[str, Any] = {
        "id_hex": id_hex,
        "label": f"cert-{id_hex}",
        "subject": f"Common Name: User {id_hex}",
        "subject_common_name": f"User {id_hex}",
        "issuer": "Common Name: Test CA",
        "issuer_common_name": "Test CA",
        "serial_number": "1a2b",
        "not_before": NOW - timedelta(days=30),
        "not_after": NOW + timedelta(days=300),
        "key_usage": frozenset({KeyUsage.DIGITAL_SIGNATURE, KeyUsage.NON_REPUDIATION}),
        "is_ca": False,
        "sha256_fingerprint": "00" * 32,
        "der": b"\x30\x00",
        "has_private_key": True,
    }
    values.update(overrides)
    return CertificateInfo(**values)


def token_info(serial: str = "TOKEN1", **overrides: Any) -> TokenInfo:
    values: dict[str, Any] = {
        "serial": serial,
        "label": f"Token {serial}",
        "manufacturer": "Feitian",
        "model": "ePass2003",
        "slot_id": 1,
        "slot_description": "ES SLOT 1",
    }
    values.update(overrides)
    return TokenInfo(**values)


@dataclass(frozen=True)
class FakeKeyHandle:
    certificate: CertificateInfo


@dataclass(frozen=True)
class InMemoryKeyHandle:
    """A key handle backed by a pyHanko software signer (for engine tests)."""

    certificate: CertificateInfo
    signer: Signer

    def to_pyhanko_signer(self) -> Signer:
        return self.signer


class FakeSession:
    def __init__(self, certificates: Sequence[CertificateInfo]) -> None:
        self._certificates = list(certificates)

    def certificates(self) -> Sequence[CertificateInfo]:
        return self._certificates

    def key_for(self, certificate: CertificateInfo) -> FakeKeyHandle:
        return FakeKeyHandle(certificate)


@dataclass
class FakeGateway:
    """Programmable TokenGateway."""

    tokens: list[TokenInfo] = field(default_factory=lambda: [token_info()])
    certificates: list[CertificateInfo] = field(default_factory=lambda: [cert_info()])
    driver: DriverStatus = field(
        default_factory=lambda: DriverStatus(
            loaded=True, module_path="/fake/libcastle.dylib", manufacturer="Feitian"
        )
    )
    login_error: AgentError | None = None
    list_error: Exception | None = None
    opened_with: list[tuple[str, str]] = field(default_factory=list)

    def driver_status(self) -> DriverStatus:
        return self.driver

    def list_tokens(self) -> Sequence[TokenInfo]:
        if self.list_error is not None:
            raise self.list_error
        return self.tokens

    def list_certificates(self, token_serial: str) -> Sequence[CertificateInfo]:
        if token_serial not in {t.serial for t in self.tokens}:
            raise TokenNotFoundError(f"No connected token has serial '{token_serial}'.")
        return list(self.certificates)

    @contextmanager
    def open_session(self, token_serial: str, pin: Pin) -> Iterator[FakeSession]:
        self.opened_with.append((token_serial, pin.reveal()))
        if self.login_error is not None:
            raise self.login_error
        yield FakeSession(self.certificates)


@dataclass
class RecordingPdfEngine:
    calls: list[tuple[Any, bytes, PdfSignatureOptions]] = field(default_factory=list)
    error: Exception | None = None

    def sign_pdf(self, key: Any, document: bytes, options: PdfSignatureOptions) -> SignedPdf:
        self.calls.append((key, document, options))
        if self.error is not None:
            raise self.error
        return SignedPdf(
            content=document + b"%signed", field_name=options.field_name or "Signature1"
        )


@dataclass
class RecordingCmsEngine:
    calls: list[tuple[Any, bytes, CmsSignatureOptions]] = field(default_factory=list)

    def sign_data(self, key: Any, data: bytes, options: CmsSignatureOptions) -> bytes:
        self.calls.append((key, data, options))
        return b"\x30\x80cms" + data[:4]


@dataclass
class RecordingAuditLog:
    events: list[AuditEvent] = field(default_factory=list)

    def record(self, event: AuditEvent) -> None:
        self.events.append(event)

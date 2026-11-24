"""Signing use cases: sign a PDF, sign arbitrary data (CMS/CAdES).

Both follow the same workflow (template method :meth:`SigningService._run`):

    resolve token → log in (exclusive) → choose certificate → engine signs → audit → result

Every attempt — successful or not — is written to the audit log (without the PIN).
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TypeVar

from sigil.domain.errors import AgentError, InvalidDocumentError
from sigil.domain.models import (
    AuditEvent,
    CertificateInfo,
    CmsSignatureOptions,
    DigestAlgorithm,
    PdfSignatureOptions,
    Pin,
    SignedPdf,
)
from sigil.domain.policies import CertificateSelectionPolicy, resolve_token
from sigil.domain.ports import (
    AuditLog,
    CmsSigningEngine,
    KeyHandle,
    PdfSigningEngine,
    TokenGateway,
)

_T = TypeVar("_T")


# --------------------------------------------------------------------------- commands


@dataclass(frozen=True, slots=True)
class SignPdfCommand:
    """Input of :meth:`SigningService.sign_pdf`."""

    pin: Pin
    document: bytes = field(repr=False)
    options: PdfSignatureOptions = field(default_factory=PdfSignatureOptions)
    token_serial: str | None = None
    certificate_id: str | None = None
    requested_by: str | None = None


@dataclass(frozen=True, slots=True)
class SignDataCommand:
    """Input of :meth:`SigningService.sign_data`."""

    pin: Pin
    data: bytes = field(repr=False)
    options: CmsSignatureOptions = field(default_factory=CmsSignatureOptions)
    token_serial: str | None = None
    certificate_id: str | None = None
    requested_by: str | None = None


# --------------------------------------------------------------------------- results


@dataclass(frozen=True, slots=True)
class PdfSigningResult:
    """A signed PDF plus who/what signed it."""

    signed: SignedPdf
    certificate: CertificateInfo
    token_serial: str


@dataclass(frozen=True, slots=True)
class DataSigningResult:
    """A DER-encoded CMS ContentInfo plus who/what signed it."""

    signature: bytes = field(repr=False)
    certificate: CertificateInfo
    token_serial: str
    digest_algorithm: DigestAlgorithm
    detached: bool


# --------------------------------------------------------------------------- service


def _utc_now() -> datetime:
    return datetime.now(UTC)


class SigningService:
    """Coordinates token access, certificate choice, signing engines and auditing."""

    def __init__(
        self,
        gateway: TokenGateway,
        pdf_engine: PdfSigningEngine,
        cms_engine: CmsSigningEngine,
        audit_log: AuditLog,
        *,
        certificate_policy: CertificateSelectionPolicy | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._gateway = gateway
        self._pdf_engine = pdf_engine
        self._cms_engine = cms_engine
        self._audit = audit_log
        self._policy = certificate_policy or CertificateSelectionPolicy()
        self._clock = clock

    # ------------------------------------------------------------------ use cases

    def sign_pdf(self, command: SignPdfCommand) -> PdfSigningResult:
        """Sign a PDF with the token key and return the signed document."""
        if not command.document:
            raise InvalidDocumentError("The uploaded PDF is empty.")

        def sign(key: KeyHandle) -> SignedPdf:
            return self._pdf_engine.sign_pdf(key, command.document, command.options)

        signed, cert, serial = self._run(
            operation="sign_pdf",
            payload=command.document,
            pin=command.pin,
            token_serial=command.token_serial,
            certificate_id=command.certificate_id,
            requested_by=command.requested_by,
            sign=sign,
        )
        return PdfSigningResult(signed=signed, certificate=cert, token_serial=serial)

    def sign_data(self, command: SignDataCommand) -> DataSigningResult:
        """Create a CMS (optionally CAdES) signature over arbitrary bytes."""
        if not command.data:
            raise InvalidDocumentError("There is no data to sign.")

        def sign(key: KeyHandle) -> bytes:
            return self._cms_engine.sign_data(key, command.data, command.options)

        signature, cert, serial = self._run(
            operation="sign_data",
            payload=command.data,
            pin=command.pin,
            token_serial=command.token_serial,
            certificate_id=command.certificate_id,
            requested_by=command.requested_by,
            sign=sign,
        )
        return DataSigningResult(
            signature=signature,
            certificate=cert,
            token_serial=serial,
            digest_algorithm=command.options.digest_algorithm,
            detached=command.options.detached,
        )

    # ------------------------------------------------------------------ workflow

    def _run(
        self,
        *,
        operation: str,
        payload: bytes,
        pin: Pin,
        token_serial: str | None,
        certificate_id: str | None,
        requested_by: str | None,
        sign: Callable[[KeyHandle], _T],
    ) -> tuple[_T, CertificateInfo, str]:
        audit_serial: str | None = token_serial
        audit_cert: str | None = certificate_id
        outcome = "INTERNAL_ERROR"
        try:
            token = resolve_token(self._gateway.list_tokens(), token_serial)
            audit_serial = token.serial
            with self._gateway.open_session(token.serial, pin) as session:
                cert = self._policy.select(session.certificates(), certificate_id, self._clock())
                audit_cert = cert.id_hex
                result = sign(session.key_for(cert))
            outcome = "SUCCESS"
            return result, cert, token.serial
        except AgentError as exc:
            outcome = exc.code
            raise
        finally:
            self._audit.record(
                AuditEvent(
                    operation=operation,
                    outcome=outcome,
                    token_serial=audit_serial,
                    certificate_id=audit_cert,
                    payload_sha256=hashlib.sha256(payload).hexdigest(),
                    payload_size=len(payload),
                    requested_by=requested_by,
                )
            )

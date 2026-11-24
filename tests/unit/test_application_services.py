"""Use cases orchestrating ports (all collaborators are fakes)."""

from __future__ import annotations

import hashlib

import pytest

from sigil.application.signing_service import (
    SignDataCommand,
    SigningService,
    SignPdfCommand,
)
from sigil.application.token_service import TokenService
from sigil.domain.errors import (
    CertificateAmbiguousError,
    InvalidDocumentError,
    PinIncorrectError,
    TokenNotFoundError,
)
from sigil.domain.models import CmsSignatureOptions, PdfSignatureOptions, Pin
from tests.support.fakes import (
    NOW,
    FakeGateway,
    RecordingAuditLog,
    RecordingCmsEngine,
    RecordingPdfEngine,
    cert_info,
    token_info,
)


@pytest.fixture
def gateway() -> FakeGateway:
    return FakeGateway(certificates=[cert_info("ca", is_ca=True), cert_info("01")])


@pytest.fixture
def audit() -> RecordingAuditLog:
    return RecordingAuditLog()


@pytest.fixture
def pdf_engine() -> RecordingPdfEngine:
    return RecordingPdfEngine()


@pytest.fixture
def cms_engine() -> RecordingCmsEngine:
    return RecordingCmsEngine()


@pytest.fixture
def service(
    gateway: FakeGateway,
    pdf_engine: RecordingPdfEngine,
    cms_engine: RecordingCmsEngine,
    audit: RecordingAuditLog,
) -> SigningService:
    return SigningService(gateway, pdf_engine, cms_engine, audit, clock=lambda: NOW)


class TestTokenService:
    def test_lists_certificates_of_the_only_token(self, gateway: FakeGateway) -> None:
        assert [c.id_hex for c in TokenService(gateway).list_certificates()] == ["ca", "01"]

    def test_unknown_serial(self, gateway: FakeGateway) -> None:
        with pytest.raises(TokenNotFoundError):
            TokenService(gateway).list_certificates("nope")

    def test_driver_status_is_passed_through(self, gateway: FakeGateway) -> None:
        assert TokenService(gateway).driver_status() is gateway.driver


class TestSignPdf:
    def test_signs_with_auto_selected_certificate_and_audits(
        self,
        service: SigningService,
        gateway: FakeGateway,
        pdf_engine: RecordingPdfEngine,
        audit: RecordingAuditLog,
    ) -> None:
        options = PdfSignatureOptions(reason="Approval")
        result = service.sign_pdf(
            SignPdfCommand(Pin("1234"), b"%PDF-doc", options, requested_by="https://erp")
        )

        assert result.signed.content == b"%PDF-doc%signed"
        assert result.certificate.id_hex == "01"
        assert result.token_serial == "TOKEN1"
        assert gateway.opened_with == [("TOKEN1", "1234")]
        key, document, used_options = pdf_engine.calls[0]
        assert key.certificate.id_hex == "01"
        assert document == b"%PDF-doc"
        assert used_options is options

        (event,) = audit.events
        assert event.operation == "sign_pdf"
        assert event.outcome == "SUCCESS"
        assert event.token_serial == "TOKEN1"
        assert event.certificate_id == "01"
        assert event.payload_sha256 == hashlib.sha256(b"%PDF-doc").hexdigest()
        assert event.payload_size == 8
        assert event.requested_by == "https://erp"
        assert "1234" not in repr(event)

    def test_empty_document_is_rejected_before_touching_the_token(
        self, service: SigningService, gateway: FakeGateway
    ) -> None:
        with pytest.raises(InvalidDocumentError):
            service.sign_pdf(SignPdfCommand(Pin("1234"), b""))
        assert gateway.opened_with == []

    def test_failures_are_audited_with_their_code(
        self, service: SigningService, gateway: FakeGateway, audit: RecordingAuditLog
    ) -> None:
        gateway.login_error = PinIncorrectError("wrong")
        with pytest.raises(PinIncorrectError):
            service.sign_pdf(SignPdfCommand(Pin("0000"), b"%PDF"))
        assert audit.events[0].outcome == "PIN_INCORRECT"
        assert audit.events[0].token_serial == "TOKEN1"

    def test_unexpected_errors_are_audited_as_internal(
        self, service: SigningService, pdf_engine: RecordingPdfEngine, audit: RecordingAuditLog
    ) -> None:
        pdf_engine.error = RuntimeError("boom")
        with pytest.raises(RuntimeError):
            service.sign_pdf(SignPdfCommand(Pin("1234"), b"%PDF"))
        assert audit.events[0].outcome == "INTERNAL_ERROR"
        assert audit.events[0].certificate_id == "01"

    def test_ambiguous_certificate_is_reported(
        self, service: SigningService, gateway: FakeGateway, audit: RecordingAuditLog
    ) -> None:
        gateway.certificates = [cert_info("01"), cert_info("02")]
        with pytest.raises(CertificateAmbiguousError):
            service.sign_pdf(SignPdfCommand(Pin("1234"), b"%PDF"))
        assert audit.events[0].outcome == "CERTIFICATE_AMBIGUOUS"

    def test_explicit_token_and_certificate(
        self, service: SigningService, gateway: FakeGateway
    ) -> None:
        gateway.tokens = [token_info("A"), token_info("B")]
        gateway.certificates = [cert_info("01"), cert_info("02")]
        result = service.sign_pdf(
            SignPdfCommand(Pin("1234"), b"%PDF", token_serial="B", certificate_id="02")
        )
        assert result.token_serial == "B"
        assert result.certificate.id_hex == "02"


class TestSignData:
    def test_returns_signature_and_metadata(
        self, service: SigningService, cms_engine: RecordingCmsEngine, audit: RecordingAuditLog
    ) -> None:
        options = CmsSignatureOptions(detached=False)
        result = service.sign_data(SignDataCommand(Pin("1234"), b"payload", options))
        assert result.signature.startswith(b"\x30\x80cms")
        assert result.detached is False
        assert result.digest_algorithm.value == "sha256"
        assert cms_engine.calls[0][1] == b"payload"
        assert audit.events[0].operation == "sign_data"

    def test_empty_data_is_rejected(self, service: SigningService) -> None:
        with pytest.raises(InvalidDocumentError):
            service.sign_data(SignDataCommand(Pin("1234"), b""))

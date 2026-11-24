"""pyHanko engines with an in-memory key; every output is cryptographically validated."""

from __future__ import annotations

import asyncio
import hashlib

import pytest
from asn1crypto import cms
from pyhanko.sign.validation.generic_cms import async_validate_detached_cms

from sigil.domain.errors import (
    FieldAlreadySignedError,
    InvalidDocumentError,
    InvalidRequestError,
    SigningError,
    TimestampError,
)
from sigil.domain.models import (
    Box,
    CmsSignatureOptions,
    DigestAlgorithm,
    KeyUsage,
    PdfSignatureOptions,
    PdfSignatureProfile,
    VisibleStamp,
)
from sigil.infrastructure.certificates import parse_certificate
from sigil.infrastructure.pyhanko_engine import (
    DEFAULT_STAMP_TEXT,
    PyHankoCmsEngine,
    PyHankoPdfEngine,
    TimestampProvider,
    _stamp_template,
)
from tests.support.fakes import FakeKeyHandle, InMemoryKeyHandle, cert_info
from tests.support.pdf import assert_all_signatures_valid, embedded_signatures, make_pdf
from tests.support.pki import TestPki, der


@pytest.fixture
def key(pki: TestPki) -> InMemoryKeyHandle:
    return InMemoryKeyHandle(pki.signer_info(), pki.simple_signer)


@pytest.fixture
def engine() -> PyHankoPdfEngine:
    return PyHankoPdfEngine(TimestampProvider(None))


class TestPdfSigning:
    def test_invisible_pades_signature_is_valid(
        self, engine: PyHankoPdfEngine, key: InMemoryKeyHandle, pki: TestPki
    ) -> None:
        signed = engine.sign_pdf(
            key, make_pdf(), PdfSignatureOptions(reason="Approval", location="Cairo")
        )
        assert signed.field_name == "Signature1"
        (status,) = assert_all_signatures_valid(signed.content, pki.validation_context())
        (sig,) = embedded_signatures(signed.content)
        assert sig.sig_object["/SubFilter"] == "/ETSI.CAdES.detached"
        assert sig.sig_object["/Reason"] == "Approval"
        assert status.signing_cert.subject.native["common_name"] == "Test Signer"

    def test_second_signature_keeps_the_first_valid(
        self, engine: PyHankoPdfEngine, key: InMemoryKeyHandle, pki: TestPki
    ) -> None:
        """Regression for audit finding #5 (hard-coded field name)."""
        once = engine.sign_pdf(key, make_pdf(), PdfSignatureOptions())
        twice = engine.sign_pdf(key, once.content, PdfSignatureOptions())
        assert twice.field_name == "Signature2"
        assert len(assert_all_signatures_valid(twice.content, pki.validation_context())) == 2

    def test_refuses_to_reuse_a_signed_field(
        self, engine: PyHankoPdfEngine, key: InMemoryKeyHandle
    ) -> None:
        once = engine.sign_pdf(key, make_pdf(), PdfSignatureOptions(field_name="Manager"))
        with pytest.raises(FieldAlreadySignedError):
            engine.sign_pdf(key, once.content, PdfSignatureOptions(field_name="Manager"))

    def test_legacy_pkcs7_profile_and_sha512(
        self, engine: PyHankoPdfEngine, key: InMemoryKeyHandle, pki: TestPki
    ) -> None:
        options = PdfSignatureOptions(
            profile=PdfSignatureProfile.PKCS7, digest_algorithm=DigestAlgorithm.SHA512
        )
        signed = engine.sign_pdf(key, make_pdf(), options)
        (status,) = assert_all_signatures_valid(signed.content, pki.validation_context())
        assert (
            embedded_signatures(signed.content)[0].sig_object["/SubFilter"]
            == "/adbe.pkcs7.detached"
        )
        assert status.md_algorithm == "sha512"

    def test_visible_stamp_on_last_page(
        self, engine: PyHankoPdfEngine, key: InMemoryKeyHandle, pki: TestPki
    ) -> None:
        stamp = VisibleStamp(box=Box(50, 60, 250, 120), page=-1, text="Approved 100% by %(signer)s")
        signed = engine.sign_pdf(key, make_pdf(pages=3), PdfSignatureOptions(stamp=stamp))
        assert_all_signatures_valid(signed.content, pki.validation_context())
        (sig,) = embedded_signatures(signed.content)
        widget = sig.sig_field
        assert [int(v) for v in widget["/Rect"]] == [50, 60, 250, 120]
        pages = sig.reader.root["/Pages"]["/Kids"]
        assert widget.raw_get("/P").reference == pages.raw_get(2).reference

    def test_page_out_of_range(self, engine: PyHankoPdfEngine, key: InMemoryKeyHandle) -> None:
        stamp = VisibleStamp(box=Box(0, 0, 10, 10), page=5)
        with pytest.raises(InvalidRequestError, match="out of range"):
            engine.sign_pdf(key, make_pdf(pages=2), PdfSignatureOptions(stamp=stamp))

    @pytest.mark.parametrize("document", [b"hello", b"%PDF-1.7 truncated garbage"])
    def test_not_a_pdf(
        self, engine: PyHankoPdfEngine, key: InMemoryKeyHandle, document: bytes
    ) -> None:
        with pytest.raises(InvalidDocumentError):
            engine.sign_pdf(key, document, PdfSignatureOptions())

    def test_encrypted_pdf_is_rejected(
        self, engine: PyHankoPdfEngine, key: InMemoryKeyHandle
    ) -> None:
        with pytest.raises(InvalidDocumentError, match="encrypted"):
            engine.sign_pdf(key, make_pdf(encrypt_password="secret"), PdfSignatureOptions())

    def test_timestamped_signature(self, key: InMemoryKeyHandle, pki: TestPki) -> None:
        engine = PyHankoPdfEngine(TimestampProvider(None, factory=pki.timestamper))
        signed = engine.sign_pdf(key, make_pdf(), PdfSignatureOptions(timestamp=True))
        (status,) = assert_all_signatures_valid(signed.content, pki.validation_context())
        assert status.timestamp_validity is not None
        assert status.timestamp_validity.intact

    def test_timestamp_without_tsa_is_a_request_error(
        self, engine: PyHankoPdfEngine, key: InMemoryKeyHandle
    ) -> None:
        with pytest.raises(InvalidRequestError, match="tsa_url"):
            engine.sign_pdf(key, make_pdf(), PdfSignatureOptions(timestamp=True))

    def test_unreachable_tsa(self, key: InMemoryKeyHandle) -> None:
        engine = PyHankoPdfEngine(TimestampProvider("http://127.0.0.1:9/tsa", timeout=2))
        with pytest.raises(TimestampError):
            engine.sign_pdf(key, make_pdf(), PdfSignatureOptions(timestamp=True))

    def test_works_when_called_from_an_event_loop_thread(
        self, engine: PyHankoPdfEngine, key: InMemoryKeyHandle, pki: TestPki
    ) -> None:
        """Regression for audit finding #1 (asyncio.run inside a running loop)."""

        async def inside_loop() -> bytes:
            return engine.sign_pdf(key, make_pdf(), PdfSignatureOptions()).content

        assert_all_signatures_valid(asyncio.run(inside_loop()), pki.validation_context())

    def test_rejects_foreign_key_handles(self, engine: PyHankoPdfEngine) -> None:
        with pytest.raises(SigningError, match="Unsupported key handle"):
            engine.sign_pdf(FakeKeyHandle(cert_info()), make_pdf(), PdfSignatureOptions())


class TestStampTemplate:
    def test_default_and_escaping(self) -> None:
        assert _stamp_template(None) == DEFAULT_STAMP_TEXT
        rendered = _stamp_template("100% by %(signer)s at %(ts)s %(other)s") % {
            "signer": "A",
            "ts": "T",
        }
        assert rendered == "100% by A at T %(other)s"


class TestCmsSigning:
    def _verify(self, signature: bytes, data: bytes, pki: TestPki) -> cms.SignedData:
        signed_data = cms.ContentInfo.load(signature)["content"]
        status = asyncio.run(
            async_validate_detached_cms(data, signed_data, pki.validation_context())
        )
        assert status.intact
        assert status.valid
        assert status.trusted
        return signed_data

    def test_detached_cades(self, key: InMemoryKeyHandle, pki: TestPki) -> None:
        data = b'{"invoice": 1}'
        signature = PyHankoCmsEngine(TimestampProvider(None)).sign_data(
            key, data, CmsSignatureOptions()
        )
        signed_data = self._verify(signature, data, pki)
        assert signed_data["encap_content_info"]["content"].native is None
        attrs = {a["type"].native for a in signed_data["signer_infos"][0]["signed_attrs"]}
        assert "signing_certificate_v2" in attrs
        digest = next(
            a["values"][0].native
            for a in signed_data["signer_infos"][0]["signed_attrs"]
            if a["type"].native == "message_digest"
        )
        assert digest == hashlib.sha256(data).digest()

    def test_embedded_content(self, key: InMemoryKeyHandle) -> None:
        options = CmsSignatureOptions(detached=False, cades=False)
        signature = PyHankoCmsEngine(TimestampProvider(None)).sign_data(key, b"abc", options)
        signed_data = cms.ContentInfo.load(signature)["content"]
        assert signed_data["encap_content_info"]["content"].native == b"abc"

    def test_timestamped(self, key: InMemoryKeyHandle, pki: TestPki) -> None:
        engine = PyHankoCmsEngine(TimestampProvider(None, factory=pki.timestamper))
        signature = engine.sign_data(key, b"abc", CmsSignatureOptions(timestamp=True))
        unsigned = cms.ContentInfo.load(signature)["content"]["signer_infos"][0]["unsigned_attrs"]
        assert any(a["type"].native == "signature_time_stamp_token" for a in unsigned)


class TestCertificateParsing:
    def test_fields(self, pki: TestPki) -> None:
        info = parse_certificate(
            der(pki.signer_cert), object_id=b"\xab", label="me", has_private_key=None
        )
        assert info.id_hex == "ab"
        assert info.subject_common_name == "Test Signer"
        assert info.issuer_common_name == "Test Root CA"
        assert info.key_usage == frozenset({KeyUsage.DIGITAL_SIGNATURE, KeyUsage.NON_REPUDIATION})
        assert not info.is_ca
        assert info.sha256_fingerprint == hashlib.sha256(der(pki.signer_cert)).hexdigest()
        assert info.serial_number == format(pki.signer_cert.serial_number, "x")
        assert pki.ca_info().is_ca

    def test_invalid_der(self) -> None:
        with pytest.raises(ValueError, match=r"Invalid X\.509"):
            parse_certificate(b"\x01\x02", object_id=b"\x01", label="x", has_private_key=None)

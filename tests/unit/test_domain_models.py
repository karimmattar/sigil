"""Domain value objects: validation and invariants."""

from __future__ import annotations

from datetime import timedelta

import pytest

from sigil.domain.errors import InvalidRequestError, PinInvalidError
from sigil.domain.models import (
    Box,
    KeyUsage,
    PdfSignatureOptions,
    Pin,
    VisibleStamp,
    normalize_certificate_id,
)
from tests.support.fakes import NOW, cert_info


class TestPin:
    def test_value_is_hidden_from_repr_str_and_formatting(self) -> None:
        pin = Pin("12345678")
        rendered = f"{pin} {pin!r} {[pin]}"
        assert "12345678" not in rendered
        assert pin.reveal() == "12345678"

    @pytest.mark.parametrize("value", ["", "123", "x" * 65, "12\n34", "1234\x00"])
    def test_rejects_malformed_pins(self, value: str) -> None:
        with pytest.raises(PinInvalidError):
            Pin(value)

    def test_rejects_non_string(self) -> None:
        with pytest.raises(PinInvalidError):
            Pin(1234)  # type: ignore[arg-type]

    @pytest.mark.parametrize("value", ["1234", "x" * 64, "pässwörd", "12 34"])
    def test_accepts_boundary_and_unicode_pins(self, value: str) -> None:
        assert Pin(value).reveal() == value


class TestBox:
    def test_parse(self) -> None:
        assert Box.parse(" 10, 20.5 ,110,80 ") == Box(10, 20.5, 110, 80)

    @pytest.mark.parametrize("text", ["1,2,3", "a,b,c,d", "1,2,3,4,5", ""])
    def test_parse_rejects_bad_syntax(self, text: str) -> None:
        with pytest.raises(InvalidRequestError):
            Box.parse(text)

    @pytest.mark.parametrize("coords", [(10, 10, 5, 20), (10, 10, 20, 10), (-1, 0, 10, 10)])
    def test_rejects_degenerate_or_negative_boxes(self, coords: tuple[int, ...]) -> None:
        with pytest.raises(InvalidRequestError):
            Box(*coords)


class TestPdfSignatureOptions:
    @pytest.mark.parametrize("name", ["Signature1", "Approver_2", "final-sign", "Sig 3"])
    def test_accepts_simple_field_names(self, name: str) -> None:
        assert PdfSignatureOptions(field_name=name).field_name == name

    @pytest.mark.parametrize("name", ["a.b", "", "x" * 65, "sig/1", "توقيع"])
    def test_rejects_field_names_pdf_would_misinterpret(self, name: str) -> None:
        with pytest.raises(InvalidRequestError):
            PdfSignatureOptions(field_name=name)

    def test_limits_metadata_length(self) -> None:
        with pytest.raises(InvalidRequestError):
            PdfSignatureOptions(reason="x" * 257)

    def test_stamp_text_length_is_limited(self) -> None:
        with pytest.raises(InvalidRequestError):
            VisibleStamp(box=Box(0, 0, 10, 10), text="x" * 501)


class TestCertificateId:
    @pytest.mark.parametrize("raw", ["0A1b", "0x0a1b", "0a:1b", " 0A 1B "])
    def test_normalizes(self, raw: str) -> None:
        assert normalize_certificate_id(raw) == "0a1b"

    @pytest.mark.parametrize("raw", ["", "abc", "zz", "0x"])
    def test_rejects_non_hex(self, raw: str) -> None:
        with pytest.raises(InvalidRequestError):
            normalize_certificate_id(raw)


class TestCertificateInfo:
    def test_validity_window(self) -> None:
        cert = cert_info()
        assert cert.is_valid_at(NOW)
        assert not cert.is_valid_at(cert.not_after + timedelta(seconds=1))
        assert not cert.is_valid_at(cert.not_before - timedelta(seconds=1))

    def test_signing_capability(self) -> None:
        assert cert_info().allows_signing
        assert cert_info(key_usage=None).allows_signing  # no extension = unrestricted
        assert not cert_info(is_ca=True).allows_signing
        assert not cert_info(key_usage=frozenset({KeyUsage.KEY_ENCIPHERMENT})).allows_signing
        assert cert_info(key_usage=frozenset({KeyUsage.DIGITAL_SIGNATURE})).allows_signing

    def test_non_repudiation_flag(self) -> None:
        assert cert_info().is_non_repudiation
        assert not cert_info(key_usage=frozenset({KeyUsage.DIGITAL_SIGNATURE})).is_non_repudiation
        assert not cert_info(key_usage=None).is_non_repudiation

    def test_der_is_not_in_repr(self) -> None:
        assert "der=" not in repr(cert_info())

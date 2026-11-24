"""Minimal PDF documents for tests, plus signature inspection helpers."""

from __future__ import annotations

from io import BytesIO
from typing import Any

from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import PdfFileWriter
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext


def make_pdf(pages: int = 1, *, encrypt_password: str | None = None) -> bytes:
    """An A4 PDF with ``pages`` empty pages (optionally AES-256 encrypted)."""
    writer = PdfFileWriter()
    for _ in range(pages):
        page = generic.DictionaryObject(
            {
                generic.NameObject("/Type"): generic.NameObject("/Page"),
                generic.NameObject("/MediaBox"): generic.ArrayObject(
                    [generic.NumberObject(n) for n in (0, 0, 595, 842)]
                ),
                generic.NameObject("/Resources"): generic.DictionaryObject(),
            }
        )
        writer.insert_page(page)
    if encrypt_password is not None:
        writer.encrypt(encrypt_password, encrypt_password)
    out = BytesIO()
    writer.write(out)
    return out.getvalue()


def embedded_signatures(signed_pdf: bytes) -> list[Any]:
    return list(PdfFileReader(BytesIO(signed_pdf)).embedded_signatures)


def assert_all_signatures_valid(signed_pdf: bytes, context: ValidationContext) -> list[Any]:
    """Validate every signature cryptographically and against the test trust root."""
    signatures = embedded_signatures(signed_pdf)
    assert signatures, "no signature found"
    statuses = []
    for sig in signatures:
        status = validate_pdf_signature(sig, context)
        assert status.intact, f"{sig.field_name}: document digest mismatch"
        assert status.valid, f"{sig.field_name}: signature invalid"
        assert status.trusted, f"{sig.field_name}: chain not trusted"
        statuses.append(status)
    return statuses

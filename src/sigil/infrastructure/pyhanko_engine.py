"""pyHanko implementations of the ``PdfSigningEngine`` and ``CmsSigningEngine`` ports.

pyHanko's signing API is asynchronous; its synchronous wrappers call ``asyncio.run``,
which crashes when invoked from a thread that already runs an event loop — exactly what
broke every ``/sign-pdf`` call of the original agent (audit finding #1). :func:`_run_sync`
runs coroutines safely from *any* thread.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from typing import Any, Protocol, TypeVar, runtime_checkable

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.misc import PdfError
from pyhanko.sign.fields import SigFieldSpec, SigSeedSubFilter, enumerate_sig_fields
from pyhanko.sign.general import SigningError as PyHankoSigningError
from pyhanko.sign.signers import PdfSignatureMetadata, PdfSigner, Signer
from pyhanko.sign.timestamps import HTTPTimeStamper, TimeStamper, TimestampRequestError
from pyhanko.stamp import TextStampStyle

from sigil.domain.errors import (
    FieldAlreadySignedError,
    InvalidDocumentError,
    InvalidRequestError,
    SigningError,
    TimestampError,
)
from sigil.domain.models import (
    CertificateInfo,
    CmsSignatureOptions,
    PdfSignatureOptions,
    PdfSignatureProfile,
    SignedPdf,
    VisibleStamp,
)
from sigil.domain.ports import KeyHandle

_T = TypeVar("_T")

DEFAULT_STAMP_TEXT = "Digitally signed by %(signer)s\nDate: %(ts)s"
_SUBFILTERS = {
    PdfSignatureProfile.PADES: SigSeedSubFilter.PADES,
    PdfSignatureProfile.PKCS7: SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
}


@runtime_checkable
class PyHankoKeyHandle(Protocol):
    """A key handle that can produce a pyHanko :class:`Signer` (e.g. ``Pkcs11KeyHandle``)."""

    @property
    def certificate(self) -> CertificateInfo: ...

    def to_pyhanko_signer(self) -> Signer: ...


# --------------------------------------------------------------------------- helpers


def _run_sync(coroutine_factory: Callable[[], Awaitable[_T]]) -> _T:
    """Run a coroutine to completion from synchronous code, whatever the calling thread."""

    async def runner() -> _T:
        return await coroutine_factory()

    try:
        asyncio.get_running_loop()
    except RuntimeError:  # the normal case: a worker thread without a loop
        return asyncio.run(runner())
    # Called from an event-loop thread: use a private loop in a helper thread.
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="pyhanko") as pool:
        return pool.submit(asyncio.run, runner()).result()


def _signer_of(key: KeyHandle) -> Signer:
    if not isinstance(key, PyHankoKeyHandle):
        raise SigningError(f"Unsupported key handle type {type(key).__name__} for pyHanko engines.")
    return key.to_pyhanko_signer()


def _reraise_token_error(exc: BaseException) -> None:
    """pyHanko sometimes wraps driver errors; surface them so the token adapter can map them."""
    cause = exc.__cause__
    if cause is not None and type(cause).__module__.startswith("pkcs11"):
        raise cause from None


def _stamp_template(text: str | None) -> str:
    """Escape ``%`` in user text while keeping the ``%(signer)s`` / ``%(ts)s`` placeholders."""
    if text is None:
        return DEFAULT_STAMP_TEXT
    escaped = text.replace("%", "%%")
    return escaped.replace("%%(signer)s", "%(signer)s").replace("%%(ts)s", "%(ts)s")


class TimestampProvider:
    """Creates RFC 3161 time-stampers for the configured TSA (one per signature).

    A new client per signature is required because pyHanko's HTTP client binds to the
    event loop it was first used on, and every signature runs on a fresh loop.
    """

    def __init__(
        self,
        tsa_url: str | None,
        *,
        timeout: float = 15.0,
        factory: Callable[[], TimeStamper] | None = None,
    ) -> None:
        self._tsa_url = tsa_url
        self._timeout = timeout
        self._factory = factory

    @property
    def available(self) -> bool:
        return self._factory is not None or self._tsa_url is not None

    def create(self) -> TimeStamper:
        if self._factory is not None:
            return self._factory()
        if self._tsa_url is None:
            raise InvalidRequestError(
                "A timestamp was requested but no time-stamping authority (tsa_url) is configured."
            )
        return HTTPTimeStamper(self._tsa_url, timeout=self._timeout)


# --------------------------------------------------------------------------- PDF


class PyHankoPdfEngine:
    """Signs PDFs incrementally (existing signatures stay valid)."""

    def __init__(self, timestamps: TimestampProvider, *, strict: bool = False) -> None:
        self._timestamps = timestamps
        self._strict = strict

    def sign_pdf(self, key: KeyHandle, document: bytes, options: PdfSignatureOptions) -> SignedPdf:
        signer = _signer_of(key)
        writer = self._open(document)
        field_name = self._choose_field_name(writer, options.field_name)
        field_spec, stamp_style = self._appearance(writer, field_name, options.stamp)
        timestamper = self._timestamps.create() if options.timestamp else None

        metadata = PdfSignatureMetadata(
            field_name=field_name,
            reason=options.reason,
            location=options.location,
            contact_info=options.contact_info,
            md_algorithm=options.digest_algorithm.value,
            subfilter=_SUBFILTERS[options.profile],
        )
        pdf_signer = PdfSigner(
            metadata,
            signer=signer,
            timestamper=timestamper,
            stamp_style=stamp_style,
            new_field_spec=field_spec,
        )
        output = BytesIO()
        try:
            _run_sync(lambda: pdf_signer.async_sign_pdf(writer, output=output))
        except TimestampRequestError as exc:
            raise TimestampError(f"Time-stamping failed: {exc}") from exc
        except PyHankoSigningError as exc:
            _reraise_token_error(exc)
            raise SigningError(f"PDF signing failed: {exc}") from exc
        except PdfError as exc:
            raise InvalidDocumentError(f"The PDF could not be signed: {exc}") from exc
        return SignedPdf(content=output.getvalue(), field_name=field_name)

    # ------------------------------------------------------------------ internals

    def _open(self, document: bytes) -> IncrementalPdfFileWriter:
        try:
            writer = IncrementalPdfFileWriter(BytesIO(document), strict=self._strict)
        except Exception as exc:  # any parser failure means "not a usable PDF"
            raise InvalidDocumentError(f"The file is not a valid PDF ({exc}).") from exc
        if writer.prev.encrypted:
            raise InvalidDocumentError("Password-protected (encrypted) PDFs cannot be signed.")
        return writer

    @staticmethod
    def _choose_field_name(writer: IncrementalPdfFileWriter, requested: str | None) -> str:
        """Use the requested field (must not be signed yet) or the first free ``SignatureN``."""
        fields: dict[str, bool] = {
            str(name): value is not None for name, value, _ in enumerate_sig_fields(writer)
        }
        if requested is not None:
            if fields.get(requested):
                raise FieldAlreadySignedError(
                    f"Signature field '{requested}' is already signed; choose another field_name."
                )
            return requested
        index = 1
        while f"Signature{index}" in fields:
            index += 1
        return f"Signature{index}"

    @staticmethod
    def _appearance(
        writer: IncrementalPdfFileWriter, field_name: str, stamp: VisibleStamp | None
    ) -> tuple[SigFieldSpec | None, TextStampStyle | None]:
        if stamp is None:
            return None, None  # pyHanko creates an invisible field
        page_count = int(writer.root["/Pages"]["/Count"])
        page = stamp.page if stamp.page >= 0 else page_count + stamp.page
        if not 0 <= page < page_count:
            raise InvalidRequestError(
                f"page {stamp.page} is out of range; the document has {page_count} page(s)."
            )
        box = (round(stamp.box.x1), round(stamp.box.y1), round(stamp.box.x2), round(stamp.box.y2))
        spec = SigFieldSpec(sig_field_name=field_name, on_page=page, box=box)
        return spec, TextStampStyle(stamp_text=_stamp_template(stamp.text))


# --------------------------------------------------------------------------- CMS


class PyHankoCmsEngine:
    """Creates CMS SignedData (CAdES-BES when ``cades=True``) over arbitrary bytes."""

    def __init__(self, timestamps: TimestampProvider) -> None:
        self._timestamps = timestamps

    def sign_data(self, key: KeyHandle, data: bytes, options: CmsSignatureOptions) -> bytes:
        signer = _signer_of(key)
        timestamper = self._timestamps.create() if options.timestamp else None
        try:
            content_info: Any = _run_sync(
                lambda: signer.async_sign_general_data(
                    data,
                    options.digest_algorithm.value,
                    detached=options.detached,
                    use_cades=options.cades,
                    timestamper=timestamper,
                )
            )
        except TimestampRequestError as exc:
            raise TimestampError(f"Time-stamping failed: {exc}") from exc
        except PyHankoSigningError as exc:
            _reraise_token_error(exc)
            raise SigningError(f"CMS signing failed: {exc}") from exc
        return bytes(content_info.dump())

"""``/api/v1`` routes.

Handlers are plain ``def`` functions on purpose: FastAPI runs them in a worker thread,
so blocking PKCS#11 calls and pyHanko's internal event loop never touch the server's
event loop (the root cause of the original agent's ``/sign-pdf`` failure).
"""

from __future__ import annotations

import base64
import binascii
import platform
import re
import struct
from typing import Annotated, Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import Response

from sigil import SERVICE_NAME, __version__
from sigil.application.signing_service import SignDataCommand, SignPdfCommand
from sigil.container import Container
from sigil.domain.errors import InvalidRequestError, PayloadTooLargeError
from sigil.domain.models import (
    Box,
    CmsSignatureOptions,
    DigestAlgorithm,
    PdfSignatureOptions,
    PdfSignatureProfile,
    Pin,
    VisibleStamp,
)

from .schemas import (
    CertificateDTO,
    CertificateListResponse,
    DriverDTO,
    ErrorResponse,
    FeaturesDTO,
    HealthResponse,
    PlatformDTO,
    SignDataRequest,
    SignDataResponse,
    TokenDTO,
    TokenListResponse,
)

#: Default visible-signature rectangle (points): bottom-left corner, 220 x 60.
DEFAULT_STAMP_BOX = Box(36, 36, 256, 96)

_ERRORS: dict[int | str, dict[str, Any]] = {
    status: {"model": ErrorResponse}
    for status in (401, 403, 404, 409, 413, 422, 423, 500, 502, 503)
}

router = APIRouter(prefix="/api/v1", responses=_ERRORS)


def get_container(request: Request) -> Container:
    """Dependency: the wired application container stored on the app."""
    container: Container = request.app.state.container
    return container


ContainerDep = Annotated[Container, Depends(get_container)]


def _requested_by(request: Request) -> str:
    return request.headers.get("origin") or "local-client"


def _header_safe(value: str) -> str:
    """HTTP header values must be Latin-1; token serials could contain anything."""
    return value.encode("ascii", errors="replace").decode("ascii")


def download_name(original: str | None) -> str:
    """``signed_<basename>.pdf`` with directories and control characters removed."""
    base = (original or "document.pdf").replace("\\", "/").rsplit("/", 1)[-1]
    base = "".join(ch for ch in base if ch.isprintable()).strip(" .") or "document.pdf"
    if not base.lower().endswith(".pdf"):
        base += ".pdf"
    return f"signed_{base[-150:]}"


def content_disposition(filename: str) -> str:
    """RFC 6266 header with an ASCII fallback and a UTF-8 ``filename*`` (Arabic names work)."""
    fallback = re.sub(r"[^A-Za-z0-9._ -]", "_", filename)
    return f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{quote(filename, safe='')}"


# --------------------------------------------------------------------------- agent


@router.get("/health", tags=["agent"], summary="Agent and driver status")
def health(container: ContainerDep) -> HealthResponse:
    """Always 200 while the agent runs; ``status`` is ``degraded`` without a usable driver."""
    driver = container.token_service.driver_status()
    bits = struct.calcsize("P") * 8
    return HealthResponse(
        service=SERVICE_NAME,
        version=__version__,
        status="ok" if driver.loaded else "degraded",
        platform=PlatformDTO(
            system=platform.system(),
            release=platform.release(),
            machine=platform.machine(),
            python=f"{platform.python_version()} ({bits}-bit)",
        ),
        driver=DriverDTO.from_domain(driver),
        features=FeaturesDTO(timestamp_available=container.timestamps_available),
    )


# --------------------------------------------------------------------------- tokens


@router.get("/tokens", tags=["tokens"], summary="Connected tokens")
def list_tokens(container: ContainerDep) -> TokenListResponse:
    tokens = container.token_service.list_tokens()
    return TokenListResponse(tokens=[TokenDTO.from_domain(t) for t in tokens])


@router.get(
    "/tokens/{token_serial}/certificates",
    tags=["tokens"],
    summary="Certificates on a token (no PIN needed)",
)
def list_certificates(token_serial: str, container: ContainerDep) -> CertificateListResponse:
    certificates = container.token_service.list_certificates(token_serial)
    return CertificateListResponse(
        token_serial=token_serial,
        certificates=[CertificateDTO.from_domain(c) for c in certificates],
    )


# --------------------------------------------------------------------------- signing


@router.post(
    "/sign/pdf",
    tags=["signing"],
    summary="Sign a PDF (PAdES or adbe.pkcs7) with the token",
    response_class=Response,
    responses={200: {"content": {"application/pdf": {}}, "description": "The signed PDF"}},
)
def sign_pdf(  # noqa: PLR0917 - FastAPI maps each form field to a parameter
    request: Request,
    container: ContainerDep,
    file: Annotated[UploadFile, File(description="The PDF to sign")],
    pin: Annotated[str, Form(description="Token user PIN (never logged)")],
    token_serial: Annotated[str | None, Form()] = None,
    cert_id: Annotated[
        str | None, Form(description="Hex certificate id; omit to auto-select")
    ] = None,
    field_name: Annotated[str | None, Form(description="Default: next free SignatureN")] = None,
    reason: Annotated[str | None, Form()] = None,
    location: Annotated[str | None, Form()] = None,
    contact_info: Annotated[str | None, Form()] = None,
    profile: Annotated[PdfSignatureProfile, Form()] = PdfSignatureProfile.PADES,
    digest_algorithm: Annotated[DigestAlgorithm, Form()] = DigestAlgorithm.SHA256,
    timestamp: Annotated[
        bool | None, Form(description="Default: true when a TSA is configured")
    ] = None,
    visible: Annotated[bool, Form(description="Draw a visible signature stamp")] = False,
    page: Annotated[int, Form(description="0-based page; -1 = last page")] = 0,
    box: Annotated[str | None, Form(description="x1,y1,x2,y2 in points from bottom-left")] = None,
    stamp_text: Annotated[str | None, Form(description="May use %(signer)s and %(ts)s")] = None,
) -> Response:
    document = file.file.read()
    if len(document) > container.settings.max_upload_bytes:
        raise PayloadTooLargeError("The PDF is larger than the configured upload limit.")

    stamp = None
    if visible:
        stamp = VisibleStamp(
            box=Box.parse(box) if box else DEFAULT_STAMP_BOX, page=page, text=stamp_text
        )
    options = PdfSignatureOptions(
        field_name=field_name or None,
        reason=reason or None,
        location=location or None,
        contact_info=contact_info or None,
        profile=profile,
        digest_algorithm=digest_algorithm,
        timestamp=container.timestamps_available if timestamp is None else timestamp,
        stamp=stamp,
    )
    result = container.signing_service.sign_pdf(
        SignPdfCommand(
            pin=Pin(pin),
            document=document,
            options=options,
            token_serial=token_serial or None,
            certificate_id=cert_id or None,
            requested_by=_requested_by(request),
        )
    )
    return Response(
        content=result.signed.content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": content_disposition(download_name(file.filename)),
            "X-Signature-Field": result.signed.field_name,
            "X-Signer-Certificate-Id": result.certificate.id_hex,
            "X-Token-Serial": _header_safe(result.token_serial),
        },
    )


@router.post(
    "/sign/data",
    tags=["signing"],
    summary="Sign arbitrary data, returning a CMS / CAdES signature",
)
def sign_data(body: SignDataRequest, request: Request, container: ContainerDep) -> SignDataResponse:
    try:
        data = base64.b64decode(body.data_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidRequestError("data_base64 is not valid base64.") from exc
    if len(data) > container.settings.max_upload_bytes:
        raise PayloadTooLargeError("The data is larger than the configured upload limit.")

    options = CmsSignatureOptions(
        detached=body.detached,
        cades=body.cades,
        digest_algorithm=body.digest_algorithm,
        timestamp=container.timestamps_available if body.timestamp is None else body.timestamp,
    )
    result = container.signing_service.sign_data(
        SignDataCommand(
            pin=Pin(body.pin.get_secret_value()),
            data=data,
            options=options,
            token_serial=body.token_serial or None,
            certificate_id=body.cert_id or None,
            requested_by=_requested_by(request),
        )
    )
    return SignDataResponse(
        signature_base64=base64.b64encode(result.signature).decode("ascii"),
        detached=result.detached,
        digest_algorithm=result.digest_algorithm,
        token_serial=result.token_serial,
        certificate=CertificateDTO.from_domain(result.certificate),
    )

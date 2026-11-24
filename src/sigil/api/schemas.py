"""Request/response DTOs of the public HTTP API (versioned under ``/api/v1``).

DTOs are deliberately separate from domain objects so the wire format can stay stable
while the domain evolves.
"""

from __future__ import annotations

import base64
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from sigil.domain.models import (
    CertificateInfo,
    DigestAlgorithm,
    DriverStatus,
    PinStatus,
    TokenInfo,
)


class _Out(BaseModel):
    model_config = ConfigDict(frozen=True)


# --------------------------------------------------------------------------- errors


class ErrorBody(_Out):
    code: str = Field(examples=["PIN_INCORRECT"])
    message: str
    details: dict[str, object] = Field(default_factory=dict)


class ErrorResponse(_Out):
    error: ErrorBody


# --------------------------------------------------------------------------- health


class DriverDTO(_Out):
    loaded: bool
    module_path: str | None
    manufacturer: str | None
    description: str | None
    library_version: str | None
    error_code: str | None
    error: str | None
    searched: list[str]

    @classmethod
    def from_domain(cls, status: DriverStatus) -> DriverDTO:
        return cls(
            loaded=status.loaded,
            module_path=status.module_path,
            manufacturer=status.manufacturer,
            description=status.description,
            library_version=status.library_version,
            error_code=status.error_code,
            error=status.error,
            searched=list(status.searched),
        )


class PlatformDTO(_Out):
    system: str
    release: str
    machine: str
    python: str


class FeaturesDTO(_Out):
    timestamp_available: bool
    pdf_profiles: list[str] = ["pades", "pkcs7"]
    digest_algorithms: list[str] = [d.value for d in DigestAlgorithm]


class HealthResponse(_Out):
    service: str
    version: str
    status: Literal["ok", "degraded"] = Field(
        description="'degraded' when the token driver is not available"
    )
    platform: PlatformDTO
    driver: DriverDTO
    features: FeaturesDTO


# --------------------------------------------------------------------------- tokens


class PinStatusDTO(_Out):
    initialized: bool
    count_low: bool
    final_try: bool
    locked: bool
    to_be_changed: bool
    protected_authentication_path: bool

    @classmethod
    def from_domain(cls, status: PinStatus) -> PinStatusDTO:
        return cls(
            initialized=status.initialized,
            count_low=status.count_low,
            final_try=status.final_try,
            locked=status.locked,
            to_be_changed=status.to_be_changed,
            protected_authentication_path=status.protected_authentication_path,
        )


class TokenDTO(_Out):
    serial: str
    label: str
    manufacturer: str
    model: str
    slot_id: int
    slot_description: str
    pin_status: PinStatusDTO

    @classmethod
    def from_domain(cls, token: TokenInfo) -> TokenDTO:
        return cls(
            serial=token.serial,
            label=token.label,
            manufacturer=token.manufacturer,
            model=token.model,
            slot_id=token.slot_id,
            slot_description=token.slot_description,
            pin_status=PinStatusDTO.from_domain(token.pin_status),
        )


class TokenListResponse(_Out):
    tokens: list[TokenDTO]


class CertificateDTO(_Out):
    cert_id: str = Field(
        description="Hex CKA_ID; send it back as cert_id to sign with this certificate"
    )
    label: str
    subject: str
    subject_common_name: str | None
    issuer: str
    issuer_common_name: str | None
    serial_number: str
    not_before: datetime
    not_after: datetime
    key_usage: list[str] | None
    is_ca: bool
    has_private_key: bool | None = Field(description="null = unknown until logged in")
    sha256_fingerprint: str
    pem: str

    @classmethod
    def from_domain(cls, cert: CertificateInfo) -> CertificateDTO:
        b64 = base64.encodebytes(cert.der).decode("ascii").replace("\n", "")
        body = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
        return cls(
            cert_id=cert.id_hex,
            label=cert.label,
            subject=cert.subject,
            subject_common_name=cert.subject_common_name,
            issuer=cert.issuer,
            issuer_common_name=cert.issuer_common_name,
            serial_number=cert.serial_number,
            not_before=cert.not_before,
            not_after=cert.not_after,
            key_usage=sorted(u.value for u in cert.key_usage)
            if cert.key_usage is not None
            else None,
            is_ca=cert.is_ca,
            has_private_key=cert.has_private_key,
            sha256_fingerprint=cert.sha256_fingerprint,
            pem=f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n",
        )


class CertificateListResponse(_Out):
    token_serial: str
    certificates: list[CertificateDTO]


# --------------------------------------------------------------------------- data signing


class SignDataRequest(BaseModel):
    """Sign arbitrary bytes (e.g. canonical JSON of an e-invoice, XML, a file)."""

    model_config = ConfigDict(extra="forbid")

    pin: SecretStr = Field(description="Token user PIN (never logged)")
    data_base64: str = Field(description="The bytes to sign, base64-encoded")
    token_serial: str | None = Field(None, description="Omit when exactly one token is connected")
    cert_id: str | None = Field(None, description="Omit to auto-select the signing certificate")
    detached: bool = Field(True, description="true = signature without embedded content")
    cades: bool = Field(
        True, description="Add CAdES-BES signed attributes (signing-certificate-v2)"
    )
    digest_algorithm: DigestAlgorithm = DigestAlgorithm.SHA256
    timestamp: bool | None = Field(
        None, description="Add an RFC 3161 timestamp; default = true when a TSA is configured"
    )


class SignDataResponse(_Out):
    signature_base64: str = Field(description="DER-encoded CMS ContentInfo (SignedData), base64")
    signature_format: Literal["CMS"] = "CMS"
    detached: bool
    digest_algorithm: DigestAlgorithm
    token_serial: str
    certificate: CertificateDTO

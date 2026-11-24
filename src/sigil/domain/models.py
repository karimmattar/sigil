"""Value objects and entities of the signing domain.

All classes are frozen dataclasses: they are validated once at construction time and
can then be passed freely between threads (the API runs signing in worker threads).
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from datetime import datetime

from .errors import InvalidRequestError, PinInvalidError

# --------------------------------------------------------------------------- PIN


@dataclass(frozen=True, slots=True, repr=False)
class Pin:
    """A token user PIN.

    The value is deliberately hidden from ``repr``/``str`` so it can never leak into
    logs, tracebacks or error messages. Call :meth:`reveal` only at the exact point
    where the PIN is handed to the token.
    """

    MIN_LENGTH = 4
    MAX_LENGTH = 64

    _value: str

    def __post_init__(self) -> None:
        if not isinstance(self._value, str):
            raise PinInvalidError("PIN must be a string.")
        if not self.MIN_LENGTH <= len(self._value) <= self.MAX_LENGTH:
            raise PinInvalidError(
                f"PIN must be between {self.MIN_LENGTH} and {self.MAX_LENGTH} characters long."
            )
        if any(not ch.isprintable() for ch in self._value):
            raise PinInvalidError("PIN contains non-printable characters.")

    def reveal(self) -> str:
        """Return the raw PIN. Use only when passing it to the token driver."""
        return self._value

    def __repr__(self) -> str:
        return "Pin('****')"

    __str__ = __repr__


# --------------------------------------------------------------------------- driver & token


@dataclass(frozen=True, slots=True)
class DriverStatus:
    """Outcome of locating and loading the PKCS#11 module (the token "driver")."""

    loaded: bool
    module_path: str | None = None
    manufacturer: str | None = None
    description: str | None = None
    library_version: str | None = None
    error_code: str | None = None
    error: str | None = None
    searched: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PinStatus:
    """User-PIN state flags as reported by the token (PKCS#11 ``CKF_USER_PIN_*``)."""

    initialized: bool = True
    count_low: bool = False
    final_try: bool = False
    locked: bool = False
    to_be_changed: bool = False
    protected_authentication_path: bool = False


@dataclass(frozen=True, slots=True)
class TokenInfo:
    """A connected, initialised token. ``serial`` is its stable identity."""

    serial: str
    label: str
    manufacturer: str
    model: str
    slot_id: int
    slot_description: str = ""
    pin_status: PinStatus = field(default_factory=PinStatus)


# --------------------------------------------------------------------------- certificates


class KeyUsage(enum.StrEnum):
    """X.509 key-usage bits (names match RFC 5280 / asn1crypto)."""

    DIGITAL_SIGNATURE = "digital_signature"
    NON_REPUDIATION = "non_repudiation"
    KEY_ENCIPHERMENT = "key_encipherment"
    DATA_ENCIPHERMENT = "data_encipherment"
    KEY_AGREEMENT = "key_agreement"
    KEY_CERT_SIGN = "key_cert_sign"
    CRL_SIGN = "crl_sign"
    ENCIPHER_ONLY = "encipher_only"
    DECIPHER_ONLY = "decipher_only"


_SIGNING_USAGES = frozenset({KeyUsage.DIGITAL_SIGNATURE, KeyUsage.NON_REPUDIATION})


@dataclass(frozen=True, slots=True)
class CertificateInfo:
    """An X.509 certificate stored on a token.

    ``id_hex`` is the PKCS#11 ``CKA_ID``: the handle that links a certificate to its
    private key and the value the web system sends back as ``cert_id``.
    ``key_usage`` is ``None`` when the certificate has no keyUsage extension (which,
    per RFC 5280, means "no restriction").
    ``has_private_key`` is ``None`` when unknown — private keys are usually invisible
    until the user has logged in with the PIN.
    """

    id_hex: str
    label: str
    subject: str
    subject_common_name: str | None
    issuer: str
    issuer_common_name: str | None
    serial_number: str
    not_before: datetime
    not_after: datetime
    key_usage: frozenset[KeyUsage] | None
    is_ca: bool
    sha256_fingerprint: str
    der: bytes = field(repr=False)
    has_private_key: bool | None = None

    def is_valid_at(self, moment: datetime) -> bool:
        """``True`` when ``moment`` lies inside the validity period."""
        return self.not_before <= moment <= self.not_after

    @property
    def allows_signing(self) -> bool:
        """End-entity certificate whose key usage permits document signatures."""
        if self.is_ca:
            return False
        return self.key_usage is None or bool(self.key_usage & _SIGNING_USAGES)

    @property
    def is_non_repudiation(self) -> bool:
        """Qualified/legal signing certificates carry the nonRepudiation bit."""
        return self.key_usage is not None and KeyUsage.NON_REPUDIATION in self.key_usage


def normalize_certificate_id(raw: str) -> str:
    """Normalise a user-supplied hex ``CKA_ID`` (accepts ``0x``, ``:``, spaces, upper case)."""
    cleaned = raw.strip().lower().removeprefix("0x").replace(":", "").replace(" ", "")
    if not cleaned or len(cleaned) % 2 or not re.fullmatch(r"[0-9a-f]+", cleaned):
        raise InvalidRequestError(
            "cert_id must be the certificate's hexadecimal id as returned by the "
            "certificates endpoint.",
            details={"cert_id": raw},
        )
    return cleaned


# --------------------------------------------------------------------------- signing options


class DigestAlgorithm(enum.StrEnum):
    """Hash algorithms accepted for signatures (SHA-1 is intentionally not offered)."""

    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"


class PdfSignatureProfile(enum.StrEnum):
    """PDF signature flavour (the PDF ``/SubFilter``)."""

    #: PAdES baseline (``ETSI.CAdES.detached``) — recommended, EU/ETSI standard.
    PADES = "pades"
    #: Legacy ``adbe.pkcs7.detached`` — for old validators that do not understand PAdES.
    PKCS7 = "pkcs7"


@dataclass(frozen=True, slots=True)
class Box:
    """Rectangle in PDF user-space points (1/72 inch), origin at the bottom-left of the page."""

    x1: float
    y1: float
    x2: float
    y2: float

    def __post_init__(self) -> None:
        if min(self.x1, self.y1, self.x2, self.y2) < 0:
            raise InvalidRequestError("Signature box coordinates must not be negative.")
        if self.x2 <= self.x1 or self.y2 <= self.y1:
            raise InvalidRequestError(
                "Signature box must be given as x1,y1,x2,y2 with x2 > x1 and y2 > y1."
            )

    @classmethod
    def parse(cls, text: str) -> Box:
        """Parse ``"x1,y1,x2,y2"``."""
        parts = [p.strip() for p in text.split(",")]
        if len(parts) != 4:
            raise InvalidRequestError(
                "box must have the form 'x1,y1,x2,y2'.", details={"box": text}
            )
        try:
            x1, y1, x2, y2 = (float(p) for p in parts)
        except ValueError as exc:
            raise InvalidRequestError(
                "box coordinates must be numbers.", details={"box": text}
            ) from exc
        return cls(x1, y1, x2, y2)


@dataclass(frozen=True, slots=True)
class VisibleStamp:
    """Visible signature appearance.

    ``page`` is 0-based; negative values count from the end (``-1`` = last page).
    ``text`` may use the placeholders ``%(signer)s`` and ``%(ts)s``; ``None`` = default text.
    """

    box: Box
    page: int = 0
    text: str | None = None

    MAX_TEXT_LENGTH = 500

    def __post_init__(self) -> None:
        if self.text is not None and len(self.text) > self.MAX_TEXT_LENGTH:
            raise InvalidRequestError(
                f"stamp_text must be at most {self.MAX_TEXT_LENGTH} characters."
            )


_FIELD_NAME_RE = re.compile(r"[A-Za-z0-9_\- ]{1,64}")
_MAX_META_LENGTH = 256


@dataclass(frozen=True, slots=True)
class PdfSignatureOptions:
    """How a PDF should be signed. ``field_name=None`` lets the engine pick ``SignatureN``."""

    field_name: str | None = None
    reason: str | None = None
    location: str | None = None
    contact_info: str | None = None
    profile: PdfSignatureProfile = PdfSignatureProfile.PADES
    digest_algorithm: DigestAlgorithm = DigestAlgorithm.SHA256
    timestamp: bool = False
    stamp: VisibleStamp | None = None

    def __post_init__(self) -> None:
        # PDF field names are dot-separated paths, so '.' (and exotic chars) are rejected.
        if self.field_name is not None and not _FIELD_NAME_RE.fullmatch(self.field_name):
            raise InvalidRequestError(
                "field_name may contain only letters, digits, '_', '-' and spaces "
                "(max 64 characters).",
                details={"field_name": self.field_name},
            )
        for name in ("reason", "location", "contact_info"):
            value = getattr(self, name)
            if value is not None and len(value) > _MAX_META_LENGTH:
                raise InvalidRequestError(f"{name} must be at most {_MAX_META_LENGTH} characters.")


@dataclass(frozen=True, slots=True)
class CmsSignatureOptions:
    """How arbitrary data should be signed (CMS / PKCS#7 SignedData)."""

    detached: bool = True
    cades: bool = True
    digest_algorithm: DigestAlgorithm = DigestAlgorithm.SHA256
    timestamp: bool = False


# --------------------------------------------------------------------------- results & audit


@dataclass(frozen=True, slots=True)
class SignedPdf:
    """Output of a PDF signing engine."""

    content: bytes = field(repr=False)
    field_name: str


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One line in the signing audit trail. Never contains the PIN or the document itself."""

    operation: str
    outcome: str
    token_serial: str | None
    certificate_id: str | None
    payload_sha256: str
    payload_size: int
    requested_by: str | None

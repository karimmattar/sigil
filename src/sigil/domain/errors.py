"""Domain errors.

Every error carries a stable, machine-readable :attr:`AgentError.code` that the web
system can switch on (e.g. show "wrong PIN, 2 tries left" for ``PIN_INCORRECT``).
Transport concerns such as HTTP status codes are mapped in the API layer, not here.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import ClassVar


class AgentError(Exception):
    """Base class for all expected (business-level) failures."""

    code: ClassVar[str] = "AGENT_ERROR"

    def __init__(self, message: str, *, details: Mapping[str, object] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details: Mapping[str, object] = MappingProxyType(dict(details or {}))


# --------------------------------------------------------------------------- driver


class DriverNotFoundError(AgentError):
    """No PKCS#11 module (token driver) is installed / configured."""

    code = "DRIVER_NOT_FOUND"


class DriverLoadError(AgentError):
    """A PKCS#11 module exists but could not be loaded (wrong architecture, broken install…)."""

    code = "DRIVER_LOAD_FAILED"


# --------------------------------------------------------------------------- token


class TokenNotFoundError(AgentError):
    """No (matching) token is connected."""

    code = "TOKEN_NOT_FOUND"


class TokenAmbiguousError(AgentError):
    """Several tokens are connected and the request did not say which one to use."""

    code = "TOKEN_AMBIGUOUS"


class TokenBusyError(AgentError):
    """The token is in use by another request and did not become free in time."""

    code = "TOKEN_BUSY"


class TokenRemovedError(AgentError):
    """The token was unplugged (or the session was lost) during the operation."""

    code = "TOKEN_REMOVED"


# --------------------------------------------------------------------------- PIN


class PinIncorrectError(AgentError):
    """The token rejected the PIN. ``details`` carries the token's retry-counter flags."""

    code = "PIN_INCORRECT"


class PinLockedError(AgentError):
    """The user PIN is blocked; it must be unblocked with the vendor's token manager."""

    code = "PIN_LOCKED"


class PinInvalidError(AgentError):
    """The PIN is malformed (length / characters) or expired."""

    code = "PIN_INVALID"


# --------------------------------------------------------------------------- certificates


class CertificateNotFoundError(AgentError):
    """No (matching) certificate with a usable private key is on the token."""

    code = "CERTIFICATE_NOT_FOUND"


class CertificateAmbiguousError(AgentError):
    """Several certificates qualify; the request must pick one via ``cert_id``."""

    code = "CERTIFICATE_AMBIGUOUS"


class CertificateNotUsableError(AgentError):
    """The requested certificate exists but cannot sign (expired, CA-only, wrong key usage)."""

    code = "CERTIFICATE_NOT_USABLE"


# --------------------------------------------------------------------------- request / document


class InvalidRequestError(AgentError):
    """A request option is invalid (bad box coordinates, page out of range, no TSA configured…)."""

    code = "INVALID_REQUEST"


class InvalidDocumentError(AgentError):
    """The submitted document cannot be signed (not a PDF, corrupt, encrypted, empty…)."""

    code = "INVALID_DOCUMENT"


class FieldAlreadySignedError(AgentError):
    """The requested signature field already contains a signature."""

    code = "FIELD_ALREADY_SIGNED"


class PayloadTooLargeError(AgentError):
    """The request body exceeds the configured size limit."""

    code = "PAYLOAD_TOO_LARGE"


# --------------------------------------------------------------------------- signing


class TimestampError(AgentError):
    """The time-stamping authority (TSA) could not be reached or returned an error."""

    code = "TIMESTAMP_FAILED"


class SigningError(AgentError):
    """Signing failed for a reason not covered above (unsupported mechanism, device error…)."""

    code = "SIGNING_FAILED"

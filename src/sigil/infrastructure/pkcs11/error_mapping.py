"""Translate python-pkcs11 exceptions into domain errors with user-actionable messages."""

from __future__ import annotations

from pkcs11 import exceptions as p11

from sigil.domain.errors import (
    AgentError,
    CertificateNotFoundError,
    PinIncorrectError,
    PinInvalidError,
    PinLockedError,
    SigningError,
    TokenBusyError,
    TokenRemovedError,
)
from sigil.domain.models import PinStatus

_REMOVED = (
    p11.DeviceRemoved,
    p11.TokenNotPresent,
    p11.TokenNotRecognised,
    p11.SessionClosed,
    p11.SessionHandleInvalid,
    p11.DeviceError,
)
_BUSY = (
    p11.SessionCount,
    p11.OperationActive,
    p11.UserAlreadyLoggedIn,
    p11.AnotherUserAlreadyLoggedIn,
    p11.SessionExists,
)
_UNSUPPORTED = (
    p11.MechanismInvalid,
    p11.MechanismParamInvalid,
    p11.FunctionNotSupported,
    p11.KeyTypeInconsistent,
)
#: Errors after which the driver is re-initialised before the next request.
_NEEDS_RESET = (*_REMOVED, p11.GeneralError, p11.DeviceMemory, p11.FunctionFailed)


def requires_reset(exc: BaseException) -> bool:
    """``True`` if the driver should be re-initialised after ``exc``."""
    return isinstance(exc, _NEEDS_RESET)


def _pin_details(status: PinStatus | None) -> dict[str, object]:
    if status is None:
        return {}
    return {"count_low": status.count_low, "final_try": status.final_try, "locked": status.locked}


def translate_pkcs11_error(exc: p11.PKCS11Error, pin_status: PinStatus | None = None) -> AgentError:
    """Map a PKCS#11 failure to the matching domain error."""
    error: AgentError
    if isinstance(exc, p11.PinIncorrect):
        message = "The PIN is incorrect."
        if pin_status is not None and pin_status.locked:
            message += " The token is now locked."
        elif pin_status is not None and pin_status.final_try:
            message += " Only ONE attempt is left before the token locks."
        elif pin_status is not None and pin_status.count_low:
            message += " Few attempts are left before the token locks."
        error = PinIncorrectError(message, details=_pin_details(pin_status))
    elif isinstance(exc, p11.PinLocked):
        error = PinLockedError(
            "The token PIN is locked. Unblock it with your token management software."
        )
    elif isinstance(exc, p11.PinLenRange | p11.PinInvalid):
        error = PinInvalidError("The PIN has an invalid length or format for this token.")
    elif isinstance(exc, p11.PinExpired):
        error = PinInvalidError(
            "The PIN has expired; change it with your token management software."
        )
    elif isinstance(exc, _REMOVED):
        error = TokenRemovedError(
            "The token was removed or stopped responding. Re-insert it and try again."
        )
    elif isinstance(exc, _BUSY):
        error = TokenBusyError("The token is busy (possibly in use by another application).")
    elif isinstance(exc, _UNSUPPORTED):
        error = SigningError(
            "The token does not support the required signature mechanism.",
            details={"pkcs11_error": type(exc).__name__},
        )
    elif isinstance(exc, p11.NoSuchKey):
        error = CertificateNotFoundError(
            "The private key of the selected certificate was not found."
        )
    else:
        error = SigningError(
            "The token reported an error.", details={"pkcs11_error": type(exc).__name__}
        )
    return error

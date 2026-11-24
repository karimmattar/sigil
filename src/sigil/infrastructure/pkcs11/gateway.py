"""python-pkcs11 implementation of the :class:`~sigil.domain.ports.TokenGateway` port.

Sessions are always opened from the single shared library object of
:class:`~.module.Pkcs11Module` — never through pyHanko's ``open_pkcs11_session``, which
would load a second library instance (see module docstring of :mod:`.module`).
"""

from __future__ import annotations

import logging
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from asn1crypto import x509
from pkcs11 import Attribute, CertificateType, ObjectClass, TokenFlag
from pkcs11 import exceptions as p11
from pyhanko.sign.pkcs11 import PKCS11Signer

from sigil.domain.errors import PinLockedError, TokenNotFoundError
from sigil.domain.models import CertificateInfo, DriverStatus, Pin, PinStatus, TokenInfo
from sigil.infrastructure.certificates import parse_certificate

from .error_mapping import requires_reset, translate_pkcs11_error
from .module import Pkcs11Module

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- helpers


def _attr(obj: Any, attribute: Attribute, default: Any) -> Any:
    """Read an optional object attribute (tokens may omit LABEL or ID)."""
    try:
        return obj[attribute]
    except (p11.AttributeTypeInvalid, p11.AttributeSensitive, KeyError):
        return default


def _token_serial(token: Any, slot_id: int) -> str:
    serial = bytes(token.serial).decode("ascii", errors="replace").strip(" \x00")
    return serial or f"slot-{slot_id}"


def _pin_status(flags: int) -> PinStatus:
    return PinStatus(
        initialized=bool(flags & TokenFlag.USER_PIN_INITIALIZED),
        count_low=bool(flags & TokenFlag.USER_PIN_COUNT_LOW),
        final_try=bool(flags & TokenFlag.USER_PIN_FINAL_TRY),
        locked=bool(flags & TokenFlag.USER_PIN_LOCKED),
        to_be_changed=bool(flags & TokenFlag.USER_PIN_TO_BE_CHANGED),
        protected_authentication_path=bool(flags & TokenFlag.PROTECTED_AUTHENTICATION_PATH),
    )


def _read_certificates(session: Any, *, logged_in: bool) -> list[CertificateInfo]:
    """Read X.509 certificates and work out which ones have a private key.

    Before login private keys are normally hidden, so a matching *public* key (same
    ``CKA_ID``) is taken as evidence; if neither is visible the answer is "unknown".
    """
    key_ids: set[bytes] = set()
    key_labels: set[str] = set()
    for key in session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY}):
        key_ids.add(bytes(_attr(key, Attribute.ID, b"")))
        key_labels.add(str(_attr(key, Attribute.LABEL, "")))
    if not logged_in:
        for key in session.get_objects({Attribute.CLASS: ObjectClass.PUBLIC_KEY}):
            key_ids.add(bytes(_attr(key, Attribute.ID, b"")))
    key_ids.discard(b"")
    key_labels.discard("")

    certificates: list[CertificateInfo] = []
    query = {
        Attribute.CLASS: ObjectClass.CERTIFICATE,
        Attribute.CERTIFICATE_TYPE: CertificateType.X_509,
    }
    for obj in session.get_objects(query):
        object_id = bytes(_attr(obj, Attribute.ID, b""))
        label = str(_attr(obj, Attribute.LABEL, ""))
        matched = object_id in key_ids if object_id else label in key_labels
        has_key: bool | None = matched if logged_in else (True if matched else None)
        try:
            der = bytes(obj[Attribute.VALUE])
            certificates.append(
                parse_certificate(der, object_id=object_id, label=label, has_private_key=has_key)
            )
        except (ValueError, p11.PKCS11Error) as exc:
            logger.warning("Skipping unreadable certificate object '%s': %s", label, exc)
    return certificates


# --------------------------------------------------------------------------- session & key


@dataclass(frozen=True)
class Pkcs11KeyHandle:
    """A private key on an open, logged-in session (implements the ``KeyHandle`` port).

    :meth:`to_pyhanko_signer` is the bridge the pyHanko engines use.
    """

    session: Any = field(repr=False)
    certificate: CertificateInfo
    ca_certificates: tuple[CertificateInfo, ...] = ()

    def to_pyhanko_signer(self) -> PKCS11Signer:
        """A pyHanko signer bound to this key; CA certificates on the token are embedded."""
        key_id = bytes.fromhex(self.certificate.id_hex) or None
        return PKCS11Signer(
            self.session,
            signing_cert=x509.Certificate.load(self.certificate.der),
            key_id=key_id,
            cert_id=key_id,
            key_label=None if key_id else self.certificate.label,
            ca_chain=[x509.Certificate.load(c.der) for c in self.ca_certificates],
            other_certs_to_pull=(),
        )


class Pkcs11SigningSession:
    """Logged-in session (implements the ``SigningSession`` port)."""

    def __init__(self, session: Any) -> None:
        self._session = session
        self._certificates: list[CertificateInfo] | None = None

    def certificates(self) -> Sequence[CertificateInfo]:
        if self._certificates is None:
            self._certificates = _read_certificates(self._session, logged_in=True)
        return self._certificates

    def key_for(self, certificate: CertificateInfo) -> Pkcs11KeyHandle:
        ca_chain = tuple(
            c for c in self.certificates() if c.is_ca and c.id_hex != certificate.id_hex
        )
        return Pkcs11KeyHandle(self._session, certificate, ca_chain)


# --------------------------------------------------------------------------- gateway


class Pkcs11TokenGateway:
    """Token discovery, certificate listing and PIN login over python-pkcs11."""

    def __init__(self, module: Pkcs11Module) -> None:
        self._module = module

    def driver_status(self) -> DriverStatus:
        return self._module.status()

    def list_tokens(self) -> list[TokenInfo]:
        with self._module.exclusive() as lib, self._translated():
            tokens = []
            for slot in lib.get_slots(token_present=True):
                found = self._initialised_token(slot)
                if found is not None:
                    tokens.append(self._token_info(slot, found))
            return tokens

    def list_certificates(self, token_serial: str) -> list[CertificateInfo]:
        with self._module.exclusive() as lib, self._translated():
            token = self._find_token(lib, token_serial)
            with token.open() as session:
                return _read_certificates(session, logged_in=False)

    @contextmanager
    def open_session(self, token_serial: str, pin: Pin) -> Iterator[Pkcs11SigningSession]:
        with self._module.exclusive() as lib:
            with self._translated(lib=lib, serial=token_serial):
                token = self._find_token(lib, token_serial)
                if token.flags & TokenFlag.USER_PIN_LOCKED:
                    # Do not even try: each attempt on a locked token is pointless.
                    raise PinLockedError(
                        "The token PIN is locked. Unblock it with your token management software."
                    )
                session = token.open(user_pin=pin.reveal())
            try:
                with self._translated():
                    yield Pkcs11SigningSession(session)
            finally:
                try:
                    session.close()  # also logs out: login state ends with the last session
                except p11.PKCS11Error as exc:
                    logger.debug("Ignoring error while closing session: %s", exc)

    # ------------------------------------------------------------------ internals

    @contextmanager
    def _translated(self, *, lib: Any = None, serial: str | None = None) -> Iterator[None]:
        """Convert PKCS#11 exceptions raised inside the block into domain errors."""
        try:
            yield
        except p11.PKCS11Error as exc:
            pin_status = None
            if isinstance(exc, p11.PinIncorrect) and lib is not None and serial is not None:
                pin_status = self._pin_status_quietly(lib, serial)
            if requires_reset(exc):
                self._module.invalidate()
            raise translate_pkcs11_error(exc, pin_status) from exc

    @staticmethod
    def _initialised_token(slot: Any) -> Any | None:
        try:
            token = slot.get_token()
        except p11.PKCS11Error:  # token pulled between enumeration and query
            return None
        # Blank (uninitialised) tokens cannot hold keys — hide them from the web system.
        return token if token.flags & TokenFlag.TOKEN_INITIALIZED else None

    @staticmethod
    def _token_info(slot: Any, token: Any) -> TokenInfo:
        return TokenInfo(
            serial=_token_serial(token, slot.slot_id),
            label=str(token.label).strip(),
            manufacturer=str(token.manufacturer_id).strip(),
            model=str(token.model).strip(),
            slot_id=int(slot.slot_id),
            slot_description=str(slot.slot_description).strip(),
            pin_status=_pin_status(int(token.flags)),
        )

    def _find_token(self, lib: Any, serial: str) -> Any:
        for slot in lib.get_slots(token_present=True):
            token = self._initialised_token(slot)
            if token is not None and _token_serial(token, slot.slot_id) == serial:
                return token
        raise TokenNotFoundError(f"No connected token has serial '{serial}'.")

    def _pin_status_quietly(self, lib: Any, serial: str) -> PinStatus | None:
        try:
            return _pin_status(int(self._find_token(lib, serial).flags))
        except (p11.PKCS11Error, TokenNotFoundError):  # best effort: only enriches a message
            return None

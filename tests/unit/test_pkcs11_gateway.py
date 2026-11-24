"""Pkcs11TokenGateway against fake python-pkcs11 objects + error translation.

The real driver path is covered end-to-end by ``tests/integration`` (SoftHSM2).
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest
from pkcs11 import Attribute, ObjectClass, TokenFlag
from pkcs11 import exceptions as p11

from sigil.domain import errors
from sigil.domain.models import Pin, PinStatus
from sigil.infrastructure.certificates import parse_certificate
from sigil.infrastructure.pkcs11.error_mapping import requires_reset, translate_pkcs11_error
from sigil.infrastructure.pkcs11.gateway import Pkcs11KeyHandle, Pkcs11TokenGateway
from sigil.infrastructure.pkcs11.locator import ModuleLocator
from sigil.infrastructure.pkcs11.module import Pkcs11Module
from tests.support.pki import TestPki, der

READY = TokenFlag.TOKEN_INITIALIZED | TokenFlag.USER_PIN_INITIALIZED | TokenFlag.LOGIN_REQUIRED


class FakeObject(dict[Attribute, Any]):
    def __getitem__(self, key: Attribute) -> Any:
        if key not in self:
            raise p11.AttributeTypeInvalid()
        return super().__getitem__(key)


class FakeSession:
    def __init__(self, token: FakeToken, logged_in: bool) -> None:
        self.token = token
        self.logged_in = logged_in
        self.closed = False

    def get_objects(self, query: dict[Attribute, Any]) -> Iterable[FakeObject]:
        kind = query[Attribute.CLASS]
        if kind == ObjectClass.PRIVATE_KEY and not self.logged_in:
            return []  # private objects are hidden before login
        return [o for o in self.token.objects if o[Attribute.CLASS] == kind]

    def close(self) -> None:
        self.closed = True
        self.token.sessions_closed += 1

    def __enter__(self) -> FakeSession:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class FakeToken:
    def __init__(
        self, serial: bytes, objects: list[FakeObject], flags: int = READY, pin: str = "1234"
    ):
        self.serial = serial
        self.label = "EgyptTrust   "
        self.manufacturer_id = "Feitian "
        self.model = "ePass2003"
        self.flags = flags
        self.objects = objects
        self.pin = pin
        self.sessions_closed = 0

    def open(self, user_pin: str | None = None) -> FakeSession:
        if user_pin is not None and user_pin != self.pin:
            self.flags |= TokenFlag.USER_PIN_COUNT_LOW
            raise p11.PinIncorrect()
        return FakeSession(self, logged_in=user_pin is not None)


class FakeSlot:
    def __init__(self, slot_id: int, token: FakeToken | Exception) -> None:
        self.slot_id = slot_id
        self.slot_description = f"ES SLOT {slot_id}  "
        self._token = token

    def get_token(self) -> FakeToken:
        if isinstance(self._token, Exception):
            raise self._token
        return self._token


class FakeLib:
    def __init__(self, slots: list[FakeSlot]) -> None:
        self.slots = slots
        self.manufacturer_id = "Fake"
        self.library_description = "Fake"
        self.library_version = (1, 0)

    def get_slots(self, token_present: bool = False) -> list[FakeSlot]:
        return self.slots

    def reinitialize(self) -> None:
        pass


def token_objects(pki: TestPki) -> list[FakeObject]:
    cert = FakeObject(
        {
            Attribute.CLASS: ObjectClass.CERTIFICATE,
            Attribute.ID: b"\x01",
            Attribute.LABEL: "signer",
            Attribute.VALUE: der(pki.signer_cert),
        }
    )
    ca = FakeObject(
        {
            Attribute.CLASS: ObjectClass.CERTIFICATE,
            Attribute.ID: b"\xca",
            Attribute.LABEL: "ca",
            Attribute.VALUE: der(pki.ca_cert),
        }
    )
    broken = FakeObject(
        {
            Attribute.CLASS: ObjectClass.CERTIFICATE,
            Attribute.LABEL: "junk",
            Attribute.VALUE: b"not a certificate",
        }
    )
    key = FakeObject({Attribute.CLASS: ObjectClass.PRIVATE_KEY, Attribute.ID: b"\x01"})
    return [cert, ca, broken, key]


def make_gateway(slots: list[FakeSlot], tmp_path: Path) -> Pkcs11TokenGateway:
    module_file = tmp_path / "fake-pkcs11.so"
    module_file.write_bytes(b"")
    lib = FakeLib(slots)
    module = Pkcs11Module(ModuleLocator(explicit=module_file), loader=lambda _path: lib)
    return Pkcs11TokenGateway(module)


@pytest.fixture
def token(pki: TestPki) -> FakeToken:
    return FakeToken(b"2C4B0001\x00\x00  ", token_objects(pki))


class TestDiscovery:
    def test_lists_initialised_tokens_only(self, token: FakeToken, tmp_path: Path) -> None:
        blank = FakeToken(b"BLANK", [], flags=0)
        gateway = make_gateway(
            [FakeSlot(1, token), FakeSlot(2, blank), FakeSlot(3, p11.TokenNotPresent())], tmp_path
        )
        (info,) = gateway.list_tokens()
        assert info.serial == "2C4B0001"
        assert info.label == "EgyptTrust"
        assert info.manufacturer == "Feitian"
        assert info.slot_description == "ES SLOT 1"
        assert info.pin_status == PinStatus(initialized=True)

    def test_empty_serial_falls_back_to_slot_id(self, tmp_path: Path) -> None:
        gateway = make_gateway([FakeSlot(7, FakeToken(b"   ", []))], tmp_path)
        assert gateway.list_tokens()[0].serial == "slot-7"

    def test_certificates_before_login_use_public_view(
        self, token: FakeToken, tmp_path: Path
    ) -> None:
        gateway = make_gateway([FakeSlot(1, token)], tmp_path)
        certs = {c.id_hex: c for c in gateway.list_certificates("2C4B0001")}
        assert set(certs) == {"01", "ca"}  # the unparsable object is skipped
        assert certs["01"].has_private_key is None  # key hidden until login
        assert certs["ca"].is_ca

    def test_public_key_counts_as_evidence_before_login(
        self, token: FakeToken, tmp_path: Path
    ) -> None:
        token.objects.append(
            FakeObject({Attribute.CLASS: ObjectClass.PUBLIC_KEY, Attribute.ID: b"\x01"})
        )
        gateway = make_gateway([FakeSlot(1, token)], tmp_path)
        certs = {c.id_hex: c for c in gateway.list_certificates("2C4B0001")}
        assert certs["01"].has_private_key is True

    def test_unknown_serial(self, token: FakeToken, tmp_path: Path) -> None:
        gateway = make_gateway([FakeSlot(1, token)], tmp_path)
        with pytest.raises(errors.TokenNotFoundError):
            gateway.list_certificates("OTHER")


class TestSessions:
    def test_logged_in_session_sees_keys_and_closes(self, token: FakeToken, tmp_path: Path) -> None:
        gateway = make_gateway([FakeSlot(1, token)], tmp_path)
        with gateway.open_session("2C4B0001", Pin("1234")) as session:
            certs = {c.id_hex: c for c in session.certificates()}
            assert certs["01"].has_private_key is True
            assert certs["ca"].has_private_key is False
            key = session.key_for(certs["01"])
            assert isinstance(key, Pkcs11KeyHandle)
            assert [c.id_hex for c in key.ca_certificates] == ["ca"]
        assert token.sessions_closed == 1

    def test_wrong_pin_reports_retry_flags(self, token: FakeToken, tmp_path: Path) -> None:
        gateway = make_gateway([FakeSlot(1, token)], tmp_path)
        with (
            pytest.raises(errors.PinIncorrectError) as exc,
            gateway.open_session("2C4B0001", Pin("9999")),
        ):
            pass
        assert exc.value.details["count_low"] is True
        assert "Few attempts" in exc.value.message

    def test_locked_token_is_not_even_tried(self, token: FakeToken, tmp_path: Path) -> None:
        token.flags |= TokenFlag.USER_PIN_LOCKED
        token.pin = "never-used"
        gateway = make_gateway([FakeSlot(1, token)], tmp_path)
        with pytest.raises(errors.PinLockedError), gateway.open_session("2C4B0001", Pin("1234")):
            pass

    def test_errors_inside_the_session_are_translated_and_session_closed(
        self, token: FakeToken, tmp_path: Path
    ) -> None:
        gateway = make_gateway([FakeSlot(1, token)], tmp_path)
        with pytest.raises(errors.TokenRemovedError), gateway.open_session("2C4B0001", Pin("1234")):
            raise p11.DeviceRemoved()
        assert token.sessions_closed == 1

    def test_key_handle_builds_pyhanko_signer(self, pki: TestPki) -> None:
        cert = parse_certificate(
            der(pki.signer_cert), object_id=b"\x01", label="signer", has_private_key=True
        )
        signer = Pkcs11KeyHandle(session=object(), certificate=cert).to_pyhanko_signer()
        assert (signer.key_id, signer.cert_id, signer.key_label) == (b"\x01", b"\x01", None)

    def test_key_handle_without_id_falls_back_to_label(self, pki: TestPki) -> None:
        cert = parse_certificate(
            der(pki.signer_cert), object_id=b"", label="signer", has_private_key=True
        )
        signer = Pkcs11KeyHandle(session=object(), certificate=cert).to_pyhanko_signer()
        assert (signer.key_id, signer.key_label) == (None, "signer")


class TestErrorTranslation:
    @pytest.mark.parametrize(
        ("exc", "expected"),
        [
            (p11.PinLocked(), errors.PinLockedError),
            (p11.PinLenRange(), errors.PinInvalidError),
            (p11.PinExpired(), errors.PinInvalidError),
            (p11.DeviceRemoved(), errors.TokenRemovedError),
            (p11.TokenNotPresent(), errors.TokenRemovedError),
            (p11.SessionCount(), errors.TokenBusyError),
            (p11.UserAlreadyLoggedIn(), errors.TokenBusyError),
            (p11.MechanismInvalid(), errors.SigningError),
            (p11.NoSuchKey(), errors.CertificateNotFoundError),
            (p11.GeneralError(), errors.SigningError),
        ],
    )
    def test_mapping(self, exc: p11.PKCS11Error, expected: type[errors.AgentError]) -> None:
        assert type(translate_pkcs11_error(exc)) is expected

    @pytest.mark.parametrize(
        ("status", "fragment"),
        [
            (PinStatus(final_try=True), "ONE attempt"),
            (PinStatus(locked=True), "now locked"),
            (PinStatus(count_low=True), "Few attempts"),
            (None, "incorrect."),
        ],
    )
    def test_pin_incorrect_messages(self, status: PinStatus | None, fragment: str) -> None:
        error = translate_pkcs11_error(p11.PinIncorrect(), status)
        assert fragment in error.message

    def test_reset_only_after_device_level_errors(self) -> None:
        assert requires_reset(p11.DeviceRemoved())
        assert requires_reset(p11.GeneralError())
        assert not requires_reset(p11.PinIncorrect())

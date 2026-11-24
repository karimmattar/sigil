"""Token resolution and certificate-selection rules."""

from __future__ import annotations

from datetime import timedelta

import pytest

from sigil.domain.errors import (
    CertificateAmbiguousError,
    CertificateNotFoundError,
    CertificateNotUsableError,
    InvalidRequestError,
    TokenAmbiguousError,
    TokenNotFoundError,
)
from sigil.domain.models import KeyUsage
from sigil.domain.policies import CertificateSelectionPolicy, resolve_token
from tests.support.fakes import NOW, cert_info, token_info

DIGITAL_ONLY = frozenset({KeyUsage.DIGITAL_SIGNATURE})


class TestResolveToken:
    def test_single_token_is_used_when_no_serial_given(self) -> None:
        token = token_info("A")
        assert resolve_token([token], None) is token
        assert resolve_token([token], "  ") is token

    def test_serial_selects_among_several(self) -> None:
        tokens = [token_info("A"), token_info("B")]
        assert resolve_token(tokens, " B ").serial == "B"

    def test_unknown_serial_lists_available_ones(self) -> None:
        with pytest.raises(TokenNotFoundError) as exc:
            resolve_token([token_info("A")], "Z")
        assert exc.value.details["available_serials"] == ["A"]

    def test_no_token(self) -> None:
        with pytest.raises(TokenNotFoundError, match="Plug in"):
            resolve_token([], None)

    def test_several_tokens_without_serial_is_ambiguous(self) -> None:
        with pytest.raises(TokenAmbiguousError) as exc:
            resolve_token([token_info("A"), token_info("B")], None)
        assert exc.value.details["available_serials"] == ["A", "B"]


class TestAutomaticCertificateSelection:
    policy = CertificateSelectionPolicy()

    def test_picks_the_only_signing_certificate(self) -> None:
        user = cert_info("01")
        chosen = self.policy.select([cert_info("ca", is_ca=True), user], None, NOW)
        assert chosen is user

    def test_prefers_non_repudiation_over_plain_digital_signature(self) -> None:
        auth = cert_info("01", key_usage=DIGITAL_ONLY)
        legal = cert_info("02")
        assert self.policy.select([auth, legal], None, NOW) is legal

    def test_falls_back_to_digital_signature_only(self) -> None:
        auth = cert_info("01", key_usage=DIGITAL_ONLY)
        assert self.policy.select([auth], None, NOW) is auth

    @pytest.mark.parametrize(
        "unusable",
        [
            cert_info("01", has_private_key=False),
            cert_info("01", has_private_key=None),
            cert_info("01", is_ca=True),
            cert_info("01", key_usage=frozenset({KeyUsage.KEY_ENCIPHERMENT})),
            cert_info("01", not_after=NOW - timedelta(days=1)),
            cert_info("01", not_before=NOW + timedelta(days=1)),
        ],
        ids=["no-key", "unknown-key", "ca", "encryption-only", "expired", "not-yet-valid"],
    )
    def test_ignores_certificates_that_cannot_sign_now(self, unusable: object) -> None:
        with pytest.raises(CertificateNotFoundError):
            self.policy.select([unusable], None, NOW)  # type: ignore[list-item]

    def test_several_candidates_are_ambiguous(self) -> None:
        with pytest.raises(CertificateAmbiguousError) as exc:
            self.policy.select([cert_info("01"), cert_info("02")], None, NOW)
        assert [c["cert_id"] for c in exc.value.details["candidates"]] == ["01", "02"]  # type: ignore[attr-defined]


class TestExplicitCertificateSelection:
    policy = CertificateSelectionPolicy()

    def test_selects_by_normalized_id(self) -> None:
        wanted = cert_info("0a1b")
        assert self.policy.select([cert_info("01"), wanted], "0x0A:1B", NOW) is wanted

    def test_unknown_id(self) -> None:
        with pytest.raises(CertificateNotFoundError):
            self.policy.select([cert_info("01")], "02", NOW)

    def test_malformed_id(self) -> None:
        with pytest.raises(InvalidRequestError):
            self.policy.select([cert_info("01")], "not-hex", NOW)

    def test_without_private_key(self) -> None:
        with pytest.raises(CertificateNotFoundError, match="no matching private key"):
            self.policy.select([cert_info("01", has_private_key=False)], "01", NOW)

    def test_unknown_key_presence_is_allowed(self) -> None:
        cert = cert_info("01", has_private_key=None)
        assert self.policy.select([cert], "01", NOW) is cert

    def test_ca_certificate_is_not_usable(self) -> None:
        with pytest.raises(CertificateNotUsableError):
            self.policy.select([cert_info("01", is_ca=True)], "01", NOW)

    def test_expired_certificate_is_not_usable(self) -> None:
        with pytest.raises(CertificateNotUsableError, match="not valid now"):
            self.policy.select([cert_info("01", not_after=NOW - timedelta(days=1))], "01", NOW)

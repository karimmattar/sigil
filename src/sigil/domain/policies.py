"""Domain policies: deterministic rules for choosing *which* token and certificate to use.

Pure functions over domain objects — trivially unit-testable and free of I/O.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from .errors import (
    CertificateAmbiguousError,
    CertificateNotFoundError,
    CertificateNotUsableError,
    TokenAmbiguousError,
    TokenNotFoundError,
)
from .models import CertificateInfo, TokenInfo, normalize_certificate_id


def resolve_token(tokens: Sequence[TokenInfo], serial: str | None) -> TokenInfo:
    """Pick the token to use.

    * With ``serial``: the token with exactly that serial.
    * Without: the only connected token — the common single-token desktop case.
    """
    if serial is not None and serial.strip():
        wanted = serial.strip()
        for token in tokens:
            if token.serial == wanted:
                return token
        raise TokenNotFoundError(
            f"No connected token has serial '{wanted}'.",
            details={"available_serials": [t.serial for t in tokens]},
        )
    if not tokens:
        raise TokenNotFoundError("No token is connected. Plug in your token and try again.")
    if len(tokens) > 1:
        raise TokenAmbiguousError(
            "Several tokens are connected; specify token_serial.",
            details={"available_serials": [t.serial for t in tokens]},
        )
    return tokens[0]


def _summary(cert: CertificateInfo) -> dict[str, object]:
    return {
        "cert_id": cert.id_hex,
        "subject": cert.subject_common_name or cert.subject,
        "not_after": cert.not_after.isoformat(),
    }


class CertificateSelectionPolicy:
    """Chooses the signing certificate on a token.

    Explicit ``cert_id``: that certificate, provided it can sign right now.

    Automatic (no ``cert_id``), candidates must:
      1. have a private key on the token,
      2. be an end-entity certificate allowed to sign (digitalSignature / nonRepudiation),
      3. be inside their validity period.
    Certificates with nonRepudiation (legal / qualified signatures) win over plain
    digitalSignature ones. If more than one candidate remains the choice is left to the
    user (``CERTIFICATE_AMBIGUOUS``) rather than guessing.
    """

    def select(
        self,
        certificates: Sequence[CertificateInfo],
        certificate_id: str | None,
        now: datetime,
    ) -> CertificateInfo:
        if certificate_id is not None:
            return self._select_explicit(
                certificates, normalize_certificate_id(certificate_id), now
            )
        return self._select_automatic(certificates, now)

    @staticmethod
    def _select_explicit(
        certificates: Sequence[CertificateInfo], wanted_id: str, now: datetime
    ) -> CertificateInfo:
        match = next((c for c in certificates if c.id_hex == wanted_id), None)
        if match is None:
            raise CertificateNotFoundError(
                f"No certificate with id '{wanted_id}' is on the token.",
                details={"available": [_summary(c) for c in certificates]},
            )
        if match.has_private_key is False:
            raise CertificateNotFoundError(
                f"Certificate '{wanted_id}' has no matching private key on the token."
            )
        if not match.allows_signing:
            raise CertificateNotUsableError(
                f"Certificate '{wanted_id}' is not allowed to create signatures "
                "(CA certificate or key usage without digitalSignature/nonRepudiation)."
            )
        if not match.is_valid_at(now):
            raise CertificateNotUsableError(
                f"Certificate '{wanted_id}' is not valid now "
                f"(valid {match.not_before.isoformat()} to {match.not_after.isoformat()}).",
            )
        return match

    @staticmethod
    def _select_automatic(
        certificates: Sequence[CertificateInfo], now: datetime
    ) -> CertificateInfo:
        candidates = [
            c
            for c in certificates
            if c.has_private_key is True and c.allows_signing and c.is_valid_at(now)
        ]
        preferred = [c for c in candidates if c.is_non_repudiation]
        if preferred:
            candidates = preferred
        if len(candidates) == 1:
            return candidates[0]
        if not candidates:
            raise CertificateNotFoundError(
                "No valid signing certificate with a private key was found on the token.",
                details={"certificates_on_token": [_summary(c) for c in certificates]},
            )
        raise CertificateAmbiguousError(
            "Several signing certificates are on the token; specify cert_id.",
            details={"candidates": [_summary(c) for c in candidates]},
        )

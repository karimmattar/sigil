"""X.509 parsing: turns DER bytes read from a token into :class:`CertificateInfo`."""

from __future__ import annotations

from asn1crypto import x509

from sigil.domain.models import CertificateInfo, KeyUsage


def _key_usage(cert: x509.Certificate) -> frozenset[KeyUsage] | None:
    value = cert.key_usage_value
    if value is None:
        return None
    known = {u.value for u in KeyUsage}
    return frozenset(KeyUsage(name) for name in value.native if name in known)


def parse_certificate(
    der: bytes, *, object_id: bytes, label: str, has_private_key: bool | None
) -> CertificateInfo:
    """Parse a DER certificate. Raises ``ValueError`` if it is not a valid X.509 certificate."""
    try:
        cert = x509.Certificate.load(der)
        subject = cert.subject
        issuer = cert.issuer
        return CertificateInfo(
            id_hex=object_id.hex(),
            label=label,
            subject=subject.human_friendly,
            subject_common_name=subject.native.get("common_name"),
            issuer=issuer.human_friendly,
            issuer_common_name=issuer.native.get("common_name"),
            serial_number=format(cert.serial_number, "x"),
            not_before=cert.not_valid_before,
            not_after=cert.not_valid_after,
            key_usage=_key_usage(cert),
            is_ca=bool(cert.ca),
            sha256_fingerprint=cert.sha256.hex(),
            der=der,
            has_private_key=has_private_key,
        )
    except (ValueError, TypeError, KeyError) as exc:
        raise ValueError(f"Invalid X.509 certificate (id={object_id.hex()}): {exc}") from exc

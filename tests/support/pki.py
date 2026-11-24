"""Throw-away PKI for tests: a CA, an end-entity signer and a TSA, built with ``cryptography``."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import cached_property

from asn1crypto import keys as asn1_keys
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pyhanko.sign.signers import SimpleSigner
from pyhanko.sign.timestamps import DummyTimeStamper
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.registry import SimpleCertificateStore

from sigil.domain.models import CertificateInfo
from sigil.infrastructure.certificates import parse_certificate

_ALL_USAGES = (
    "digital_signature",
    "content_commitment",  # = nonRepudiation in cryptography's naming
    "key_encipherment",
    "data_encipherment",
    "key_agreement",
    "key_cert_sign",
    "crl_sign",
    "encipher_only",
    "decipher_only",
)


def new_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def issue(
    subject_cn: str,
    key: rsa.RSAPrivateKey,
    *,
    issuer: tuple[x509.Certificate, rsa.RSAPrivateKey] | None = None,
    ca: bool = False,
    usages: tuple[str, ...] | None = ("digital_signature", "content_commitment"),
    eku: list[x509.ObjectIdentifier] | None = None,
    valid_from: datetime | None = None,
    valid_days: int = 365,
) -> x509.Certificate:
    """Issue a certificate (self-signed when ``issuer`` is None)."""
    now = valid_from or datetime.now(UTC) - timedelta(minutes=5)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer_name, issuer_key = (issuer[0].subject, issuer[1]) if issuer else (subject, key)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if usages is not None:
        flags = {name: name in usages for name in _ALL_USAGES}
        if not flags["key_agreement"]:
            flags["encipher_only"] = flags["decipher_only"] = False
        builder = builder.add_extension(x509.KeyUsage(**flags), critical=True)
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=True)
    return builder.sign(issuer_key, hashes.SHA256())


def der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def to_asn1_cert(cert: x509.Certificate) -> asn1_x509.Certificate:
    return asn1_x509.Certificate.load(der(cert))


def to_asn1_key(key: rsa.RSAPrivateKey) -> asn1_keys.PrivateKeyInfo:
    return asn1_keys.PrivateKeyInfo.load(
        key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


@dataclass(frozen=True)
class TestPki:
    """CA → signer, plus a time-stamping authority issued by the same CA."""

    __test__ = False  # not a pytest test class

    ca_key: rsa.RSAPrivateKey
    ca_cert: x509.Certificate
    signer_key: rsa.RSAPrivateKey
    signer_cert: x509.Certificate
    tsa_key: rsa.RSAPrivateKey
    tsa_cert: x509.Certificate

    @classmethod
    def create(cls, signer_cn: str = "Test Signer") -> TestPki:
        ca_key, signer_key, tsa_key = new_key(), new_key(), new_key()
        ca_cert = issue("Test Root CA", ca_key, ca=True, usages=("key_cert_sign", "crl_sign"))
        signer_cert = issue(signer_cn, signer_key, issuer=(ca_cert, ca_key))
        tsa_cert = issue(
            "Test TSA",
            tsa_key,
            issuer=(ca_cert, ca_key),
            usages=("digital_signature",),
            eku=[ExtendedKeyUsageOID.TIME_STAMPING],
        )
        return cls(ca_key, ca_cert, signer_key, signer_cert, tsa_key, tsa_cert)

    # ---- domain views ---------------------------------------------------------------------
    def signer_info(
        self, id_hex: str = "01", has_private_key: bool | None = True
    ) -> CertificateInfo:
        return parse_certificate(
            der(self.signer_cert),
            object_id=bytes.fromhex(id_hex),
            label="signer",
            has_private_key=has_private_key,
        )

    def ca_info(self, id_hex: str = "ca") -> CertificateInfo:
        return parse_certificate(
            der(self.ca_cert), object_id=bytes.fromhex(id_hex), label="ca", has_private_key=False
        )

    # ---- pyHanko helpers --------------------------------------------------------------------
    @cached_property
    def simple_signer(self) -> SimpleSigner:
        return SimpleSigner(
            signing_cert=to_asn1_cert(self.signer_cert),
            signing_key=to_asn1_key(self.signer_key),
            cert_registry=SimpleCertificateStore.from_certs([to_asn1_cert(self.ca_cert)]),
        )

    def timestamper(self) -> DummyTimeStamper:
        return DummyTimeStamper(
            tsa_cert=to_asn1_cert(self.tsa_cert),
            tsa_key=to_asn1_key(self.tsa_key),
            certs_to_embed=SimpleCertificateStore.from_certs([to_asn1_cert(self.ca_cert)]),
        )

    def validation_context(self) -> ValidationContext:
        return ValidationContext(trust_roots=[to_asn1_cert(self.ca_cert)], allow_fetching=False)

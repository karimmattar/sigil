"""Provision a SoftHSM2 software token for integration tests.

Key/certificate import runs in a *separate process* so that provisioning never shares
PKCS#11 state (initialisation, sessions, login) with the agent under test.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from tests.support.pki import TestPki, der

MODULE_CANDIDATES = (
    "/opt/homebrew/lib/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib64/pkcs11/libsofthsm2.so",
)

TOKEN_LABEL = "AgentTest"
USER_PIN = "246810"
SO_PIN = "13579135"
SIGNER_ID = b"\x01"
CA_ID = b"\xca"

_IMPORT_SCRIPT = r"""
import sys
from pathlib import Path
import pkcs11
from pkcs11 import Attribute, ObjectClass, KeyType, CertificateType
from pkcs11.util.rsa import decode_rsa_private_key, decode_rsa_public_key
from pkcs11.util.x509 import decode_x509_certificate

module, label, pin, workdir = sys.argv[1:5]
work = Path(workdir)
lib = pkcs11.lib(module)
token = lib.get_token(token_label=label)
with token.open(rw=True, user_pin=pin) as session:
    common = {Attribute.TOKEN: True, Attribute.ID: b"\x01", Attribute.LABEL: "Test Signer"}
    priv = decode_rsa_private_key((work / "signer.key.der").read_bytes())
    priv.update(common)
    priv.update({Attribute.PRIVATE: True, Attribute.SENSITIVE: True, Attribute.SIGN: True})
    session.create_object(priv)
    pub = decode_rsa_public_key((work / "signer.pub.der").read_bytes())
    pub.update(common)
    pub.update({Attribute.VERIFY: True})
    session.create_object(pub)
    certs = (("signer", b"\x01", "Test Signer"), ("ca", b"\xca", "Test Root CA"))
    for name, obj_id, obj_label in certs:
        cert = decode_x509_certificate((work / f"{name}.crt.der").read_bytes())
        cert.update({Attribute.TOKEN: True, Attribute.ID: obj_id, Attribute.LABEL: obj_label})
        session.create_object(cert)
"""


@dataclass(frozen=True)
class SoftHsmToken:
    module: Path
    conf: Path
    label: str = TOKEN_LABEL
    pin: str = USER_PIN


def find_softhsm() -> tuple[Path, str] | None:
    """``(module, softhsm2-util)`` if SoftHSM2 is installed, else ``None``."""
    util = shutil.which("softhsm2-util")
    candidates = [os.environ.get("SOFTHSM2_MODULE", ""), *MODULE_CANDIDATES]
    module = next((Path(c) for c in candidates if c and Path(c).is_file()), None)
    return (module, util) if module and util else None


def provision(workdir: Path, pki: TestPki) -> SoftHsmToken:
    """Create a fresh token with the PKI's signer key + certificate and the CA certificate."""
    found = find_softhsm()
    assert found is not None
    module, util = found
    (workdir / "tokens").mkdir(parents=True)
    conf = workdir / "softhsm2.conf"
    conf.write_text(
        f"directories.tokendir = {workdir / 'tokens'}\n"
        "objectstore.backend = file\n"
        "log.level = ERROR\n"
    )
    env = {**os.environ, "SOFTHSM2_CONF": str(conf)}
    subprocess.run(
        [
            util,
            "--init-token",
            "--free",
            "--label",
            TOKEN_LABEL,
            "--pin",
            USER_PIN,
            "--so-pin",
            SO_PIN,
        ],
        env=env,
        check=True,
        capture_output=True,
    )
    key = pki.signer_key
    (workdir / "signer.key.der").write_bytes(
        key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    (workdir / "signer.pub.der").write_bytes(
        key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
    )
    (workdir / "signer.crt.der").write_bytes(der(pki.signer_cert))
    (workdir / "ca.crt.der").write_bytes(der(pki.ca_cert))
    subprocess.run(
        [sys.executable, "-c", _IMPORT_SCRIPT, str(module), TOKEN_LABEL, USER_PIN, str(workdir)],
        env=env,
        check=True,
        capture_output=True,
    )
    return SoftHsmToken(module=module, conf=conf)

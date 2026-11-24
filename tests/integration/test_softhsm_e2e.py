"""End-to-end: HTTP API → services → python-pkcs11 → SoftHSM2 token → pyHanko, verified.

Skipped automatically when SoftHSM2 is not installed
(macOS: ``brew install softhsm``; Debian/Ubuntu: ``apt install softhsm2``).
"""

from __future__ import annotations

import asyncio
import base64
import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pkcs11
import pytest
from asn1crypto import cms
from fastapi.testclient import TestClient
from pyhanko.sign.validation.generic_cms import async_validate_detached_cms

from sigil.api import create_app
from sigil.application.signing_service import SignPdfCommand
from sigil.container import Container, build_container
from sigil.domain.models import PdfSignatureOptions, Pin
from sigil.infrastructure.config import AgentSettings
from tests.support.fakes import RecordingAuditLog
from tests.support.pdf import assert_all_signatures_valid, embedded_signatures, make_pdf
from tests.support.pki import TestPki
from tests.support.softhsm import USER_PIN, SoftHsmToken, find_softhsm, provision

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(find_softhsm() is None, reason="SoftHSM2 is not installed"),
]

WEB_APP = "https://erp.example.com"


@pytest.fixture(scope="module")
def token(tmp_path_factory: pytest.TempPathFactory, pki: TestPki) -> Iterator[SoftHsmToken]:
    provisioned = provision(tmp_path_factory.mktemp("softhsm"), pki)
    previous = os.environ.get("SOFTHSM2_CONF")
    os.environ["SOFTHSM2_CONF"] = str(provisioned.conf)  # read by SoftHSM at C_Initialize
    yield provisioned
    if previous is None:
        os.environ.pop("SOFTHSM2_CONF", None)
    else:
        os.environ["SOFTHSM2_CONF"] = previous


class Agent:
    """The one real container for this module (a PKCS#11 module is initialised once per process)."""

    def __init__(self, token: SoftHsmToken, pki: TestPki) -> None:
        self.loads: list[str] = []

        def counting_loader(path: str) -> Any:
            self.loads.append(path)
            return pkcs11.lib(path)

        self.audit = RecordingAuditLog()
        self.container: Container = build_container(
            AgentSettings(pkcs11_module=token.module, allowed_origins=(WEB_APP,)),
            module_loader=counting_loader,
            timestamper_factory=pki.timestamper,
            audit_log=self.audit,
        )
        self.client = TestClient(create_app(self.container), base_url="http://127.0.0.1:8765")

    def sign_pdf(self, pdf: bytes, **form: Any) -> Any:
        return self.client.post(
            "/api/v1/sign/pdf",
            data={"pin": USER_PIN, **form},
            files={"file": ("doc.pdf", pdf, "application/pdf")},
            headers={"Origin": WEB_APP},
        )


@pytest.fixture(scope="module")
def agent(token: SoftHsmToken, pki: TestPki) -> Agent:
    return Agent(token, pki)


def test_health_reports_the_loaded_driver(agent: Agent) -> None:
    body = agent.client.get("/api/v1/health").json()
    assert body["status"] == "ok"
    assert body["driver"]["manufacturer"] == "SoftHSM"
    assert body["features"]["timestamp_available"] is True


def test_token_and_certificates_are_listed_without_pin(agent: Agent) -> None:
    (token,) = agent.client.get("/api/v1/tokens").json()["tokens"]
    assert token["label"] == "AgentTest"
    certs = agent.client.get(f"/api/v1/tokens/{token['serial']}/certificates").json()[
        "certificates"
    ]
    by_id = {c["cert_id"]: c for c in certs}
    assert by_id["01"]["subject_common_name"] == "Test Signer"
    assert by_id["01"]["has_private_key"] is True  # public key object is visible
    assert by_id["ca"]["is_ca"] is True


def test_sign_pdf_end_to_end_with_auto_selected_certificate(agent: Agent, pki: TestPki) -> None:
    response = agent.sign_pdf(make_pdf(), reason="Integration test", timestamp="false")
    assert response.status_code == 200, response.text
    assert response.headers["x-signer-certificate-id"] == "01"
    (status,) = assert_all_signatures_valid(response.content, pki.validation_context())
    assert status.signing_cert.subject.native["common_name"] == "Test Signer"
    sig = embedded_signatures(response.content)[0]
    embedded = {c.chosen.subject.native["common_name"] for c in sig.signed_data["certificates"]}
    assert "Test Root CA" in embedded  # CA certificate from the token is embedded


def test_visible_timestamped_second_signature(agent: Agent, pki: TestPki) -> None:
    first = agent.sign_pdf(make_pdf(pages=2), timestamp="false").content
    response = agent.sign_pdf(first, visible="true", page="-1", box="300,40,560,110", cert_id="01")
    assert response.status_code == 200, response.text
    assert response.headers["x-signature-field"] == "Signature2"
    statuses = assert_all_signatures_valid(response.content, pki.validation_context())
    assert statuses[1].timestamp_validity is not None  # TSA is configured → timestamped by default


def test_legacy_pkcs7_profile(agent: Agent, pki: TestPki) -> None:
    response = agent.sign_pdf(
        make_pdf(), profile="pkcs7", digest_algorithm="sha384", timestamp="false"
    )
    assert response.status_code == 200, response.text
    (status,) = assert_all_signatures_valid(response.content, pki.validation_context())
    assert status.md_algorithm == "sha384"


def test_sign_data_detached_cades(agent: Agent, pki: TestPki) -> None:
    data = b'{"documentType":"I","totalAmount":100.0}'
    response = agent.client.post(
        "/api/v1/sign/data",
        json={"pin": USER_PIN, "data_base64": base64.b64encode(data).decode(), "timestamp": False},
        headers={"Origin": WEB_APP},
    )
    assert response.status_code == 200, response.text
    signed_data = cms.ContentInfo.load(base64.b64decode(response.json()["signature_base64"]))[
        "content"
    ]
    status = asyncio.run(async_validate_detached_cms(data, signed_data, pki.validation_context()))
    assert status.intact
    assert status.valid
    assert status.trusted


def test_wrong_pin_then_correct_pin(agent: Agent) -> None:
    wrong = agent.sign_pdf(make_pdf(), pin="000000", timestamp="false")
    assert wrong.status_code == 401
    assert wrong.json()["error"]["code"] == "PIN_INCORRECT"
    assert agent.sign_pdf(make_pdf(), timestamp="false").status_code == 200


def test_unknown_token_and_certificate(agent: Agent) -> None:
    assert (
        agent.sign_pdf(make_pdf(), token_serial="nope").json()["error"]["code"] == "TOKEN_NOT_FOUND"
    )
    assert (
        agent.sign_pdf(make_pdf(), cert_id="99").json()["error"]["code"] == "CERTIFICATE_NOT_FOUND"
    )


def test_concurrent_requests_are_serialised_safely(agent: Agent, pki: TestPki) -> None:
    """Regression for audit finding #3: parallel logins must not collide."""
    service = agent.container.signing_service
    options_pdf = make_pdf()

    def sign(_: int) -> bytes:
        result = service.sign_pdf(SignPdfCommand(Pin(USER_PIN), options_pdf, PdfSignatureOptions()))
        return result.signed.content

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(sign, range(6)))
    for content in results:
        assert_all_signatures_valid(content, pki.validation_context())


def test_driver_was_loaded_exactly_once(agent: Agent, token: SoftHsmToken) -> None:
    """Discovery and loading happen once; later requests reuse the loaded module."""
    agent.client.get("/api/v1/tokens")
    assert agent.loads == [str(token.module)]


def test_every_signature_attempt_was_audited(agent: Agent) -> None:
    outcomes = {e.outcome for e in agent.audit.events}
    assert {"SUCCESS", "PIN_INCORRECT", "TOKEN_NOT_FOUND", "CERTIFICATE_NOT_FOUND"} <= outcomes
    assert all(USER_PIN not in repr(e) for e in agent.audit.events)


def test_softhsm_module_path_is_used(token: SoftHsmToken) -> None:
    assert Path(token.module).name == "libsofthsm2.so"

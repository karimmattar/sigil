"""HTTP API: routes, error contract and security middleware (services backed by fakes)."""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Callable
from typing import Any

import pytest

from sigil.api.routes import content_disposition, download_name
from sigil.api.security import BodySizeLimitMiddleware, host_without_port
from sigil.domain.errors import PinIncorrectError, TokenBusyError
from sigil.domain.models import DriverStatus
from tests.support.harness import WEB_APP, Harness

PIN = "12345678"


@pytest.fixture
def harness() -> Harness:
    return Harness()


def sign_pdf(harness: Harness, **form: Any) -> Any:
    data = {"pin": PIN, **form}
    files = {"file": (form.pop("filename", "contract.pdf"), b"%PDF-1.7 test", "application/pdf")}
    return harness.client.post(
        "/api/v1/sign/pdf", data=data, files=files, headers={"Origin": WEB_APP}
    )


def assert_error(response: Any, status: int, code: str) -> dict[str, Any]:
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()["error"]
    assert body["code"] == code
    assert set(body) == {"code", "message", "details"}
    return body


class TestHealthAndTokens:
    def test_health_ok(self, harness: Harness) -> None:
        body = harness.client.get("/api/v1/health").json()
        assert body["service"] == "sigil"
        assert body["status"] == "ok"
        assert body["driver"]["module_path"] == "/fake/libcastle.dylib"
        assert body["features"]["timestamp_available"] is False

    def test_health_degraded_without_driver(self, harness: Harness) -> None:
        harness.gateway.driver = DriverStatus(
            loaded=False, error_code="DRIVER_NOT_FOUND", error="none"
        )
        response = harness.client.get("/api/v1/health")
        assert response.status_code == 200
        assert response.json()["status"] == "degraded"

    def test_tokens(self, harness: Harness) -> None:
        (token,) = harness.client.get("/api/v1/tokens").json()["tokens"]
        assert token["serial"] == "TOKEN1"
        assert token["pin_status"]["locked"] is False

    def test_certificates_include_pem(self, harness: Harness) -> None:
        body = harness.client.get("/api/v1/tokens/TOKEN1/certificates").json()
        assert [c["cert_id"] for c in body["certificates"]] == ["ca", "01"]
        assert body["certificates"][1]["pem"].startswith("-----BEGIN CERTIFICATE-----\n")
        assert body["certificates"][1]["key_usage"] == ["digital_signature", "non_repudiation"]

    def test_unknown_token(self, harness: Harness) -> None:
        assert_error(harness.client.get("/api/v1/tokens/NOPE/certificates"), 404, "TOKEN_NOT_FOUND")

    def test_busy_token(self, harness: Harness) -> None:
        harness.gateway.list_error = TokenBusyError("busy")
        assert_error(harness.client.get("/api/v1/tokens"), 409, "TOKEN_BUSY")


class TestSignPdf:
    def test_success_returns_pdf_and_metadata_headers(self, harness: Harness) -> None:
        response = sign_pdf(harness, reason="Approval", filename="عقد.pdf")
        assert response.status_code == 200, response.text
        assert response.headers["content-type"] == "application/pdf"
        assert response.content == b"%PDF-1.7 test%signed"
        assert response.headers["x-signature-field"] == "Signature1"
        assert response.headers["x-signer-certificate-id"] == "01"
        assert response.headers["x-token-serial"] == "TOKEN1"
        assert "filename*=UTF-8''signed_%D8%B9" in response.headers["content-disposition"]
        assert response.headers["access-control-allow-origin"] == WEB_APP
        assert "X-Signature-Field" in response.headers["access-control-expose-headers"]
        assert response.headers["cache-control"] == "no-store"
        _, _, options = harness.pdf_engine.calls[0]
        assert options.reason == "Approval"
        assert options.timestamp is False
        assert options.stamp is None
        assert harness.audit.events[0].requested_by == WEB_APP

    def test_visible_stamp_defaults_and_custom_box(self, harness: Harness) -> None:
        sign_pdf(harness, visible="true")
        sign_pdf(harness, visible="true", page="-1", box="10,20,110,70", stamp_text="OK")
        default, custom = (call[2].stamp for call in harness.pdf_engine.calls)
        assert (default.box.x1, default.box.y2, default.page) == (36, 96, 0)
        assert (custom.box.x1, custom.box.y1, custom.page, custom.text) == (10, 20, -1, "OK")

    def test_timestamp_defaults_to_tsa_availability(self) -> None:
        harness = Harness(timestamps=True)
        sign_pdf(harness)
        sign_pdf(harness, timestamp="false")
        assert [c[2].timestamp for c in harness.pdf_engine.calls] == [True, False]

    def test_wrong_pin(self, harness: Harness) -> None:
        harness.gateway.login_error = PinIncorrectError("wrong", details={"final_try": True})
        body = assert_error(sign_pdf(harness), 401, "PIN_INCORRECT")
        assert body["details"]["final_try"] is True

    def test_malformed_pin_never_reaches_the_token(self, harness: Harness) -> None:
        assert_error(sign_pdf(harness, pin="12"), 422, "PIN_INVALID")
        assert harness.gateway.opened_with == []

    def test_invalid_box(self, harness: Harness) -> None:
        assert_error(sign_pdf(harness, visible="true", box="1,2"), 422, "INVALID_REQUEST")

    def test_validation_errors_do_not_echo_the_pin(self, harness: Harness) -> None:
        response = harness.client.post(
            "/api/v1/sign/pdf", data={"pin": "s3cr3t-pin", "page": "x"}, headers={"Origin": WEB_APP}
        )
        body = assert_error(response, 422, "VALIDATION_ERROR")
        assert "s3cr3t-pin" not in response.text
        assert {e["field"] for e in body["details"]["errors"]} == {"file", "page"}

    def test_unexpected_error_is_500_with_correlation_id_and_cors(self, harness: Harness) -> None:
        harness.pdf_engine.error = RuntimeError("driver exploded: secret internals")
        response = sign_pdf(harness)
        body = assert_error(response, 500, "INTERNAL_ERROR")
        assert len(body["details"]["correlation_id"]) == 12
        assert "secret internals" not in response.text
        assert response.headers["access-control-allow-origin"] == WEB_APP


class TestSignData:
    def post(self, harness: Harness, **payload: Any) -> Any:
        body = {"pin": PIN, "data_base64": base64.b64encode(b"invoice").decode(), **payload}
        return harness.client.post("/api/v1/sign/data", json=body, headers={"Origin": WEB_APP})

    def test_success(self, harness: Harness) -> None:
        response = self.post(harness, detached=False, digest_algorithm="sha384")
        assert response.status_code == 200, response.text
        body = response.json()
        assert base64.b64decode(body["signature_base64"]).startswith(b"\x30\x80cms")
        assert body["detached"] is False
        assert body["digest_algorithm"] == "sha384"
        assert body["certificate"]["cert_id"] == "01"
        assert harness.cms_engine.calls[0][1] == b"invoice"

    def test_invalid_base64(self, harness: Harness) -> None:
        assert_error(self.post(harness, data_base64="***"), 422, "INVALID_REQUEST")

    def test_unknown_fields_are_rejected_without_echoing_the_pin(self, harness: Harness) -> None:
        response = self.post(harness, pin="topsecret1", surprise=1)
        assert_error(response, 422, "VALIDATION_ERROR")
        assert "topsecret1" not in response.text


class TestSecurity:
    @pytest.mark.parametrize(
        "origin", ["https://evil.example", "null", "https://erp.example.com.evil.io"]
    )
    def test_foreign_origins_are_rejected_before_any_token_access(
        self, harness: Harness, origin: str
    ) -> None:
        response = harness.client.post(
            "/api/v1/sign/pdf",
            data={"pin": PIN},
            files={"file": ("a.pdf", b"%PDF", "application/pdf")},
            headers={"Origin": origin},
        )
        assert_error(response, 403, "ORIGIN_NOT_ALLOWED")
        assert harness.gateway.opened_with == []
        assert "access-control-allow-origin" not in response.headers

    def test_requests_without_origin_are_local_clients(self, harness: Harness) -> None:
        assert harness.client.get("/api/v1/tokens").status_code == 200

    def test_agent_own_docs_origin_is_allowed(self, harness: Harness) -> None:
        response = harness.client.get("/api/v1/tokens", headers={"Origin": "http://127.0.0.1:8765"})
        assert response.status_code == 200

    @pytest.mark.parametrize("host", ["evil.example", "attacker.com:8765", "192.168.1.5:8765"])
    def test_dns_rebinding_hosts_are_rejected(self, harness: Harness, host: str) -> None:
        assert_error(
            harness.client.get("/api/v1/health", headers={"Host": host}), 403, "HOST_NOT_ALLOWED"
        )

    @pytest.mark.parametrize("host", ["localhost:8765", "127.0.0.1", "[::1]:8765"])
    def test_loopback_hosts_are_accepted(self, harness: Harness, host: str) -> None:
        assert harness.client.get("/api/v1/health", headers={"Host": host}).status_code == 200

    def test_cors_preflight_with_private_network_access(self, harness: Harness) -> None:
        response = harness.client.options(
            "/api/v1/sign/pdf",
            headers={
                "Origin": WEB_APP,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
                "Access-Control-Request-Private-Network": "true",
            },
        )
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == WEB_APP
        assert response.headers["access-control-allow-private-network"] == "true"

    def test_preflight_from_foreign_origin_is_rejected(self, harness: Harness) -> None:
        response = harness.client.options(
            "/api/v1/sign/pdf",
            headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
        )
        assert_error(response, 403, "ORIGIN_NOT_ALLOWED")

    def test_oversized_upload(self) -> None:
        harness = Harness(max_upload_mb=1)
        response = harness.client.post(
            "/api/v1/sign/pdf",
            data={"pin": PIN},
            files={"file": ("big.pdf", b"0" * (1024 * 1024 + 10), "application/pdf")},
            headers={"Origin": WEB_APP},
        )
        assert_error(response, 413, "PAYLOAD_TOO_LARGE")
        assert response.headers["access-control-allow-origin"] == WEB_APP
        assert harness.gateway.opened_with == []

    def test_security_headers(self, harness: Harness) -> None:
        headers = harness.client.get("/api/v1/health").headers
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["x-frame-options"] == "DENY"
        assert "server" not in headers

    def test_unknown_route_uses_error_contract(self, harness: Harness) -> None:
        assert_error(harness.client.get("/sign-pdf"), 404, "NOT_FOUND")
        assert_error(harness.client.get("/api/v1/sign/pdf"), 405, "METHOD_NOT_ALLOWED")

    def test_docs_can_be_disabled(self) -> None:
        assert Harness().client.get("/docs").status_code == 200
        assert Harness(enable_docs=False).client.get("/docs").status_code == 404


class TestBodySizeLimitStreaming:
    """Chunked uploads have no Content-Length; the limit must still hold."""

    async def _run(self, chunks: list[bytes], limit: int) -> list[dict[str, Any]]:
        async def app(scope: Any, receive: Callable[[], Any], send: Callable[[Any], Any]) -> None:
            while True:
                message = await receive()
                if not message.get("more_body"):
                    break
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        messages = iter(
            [
                {"type": "http.request", "body": c, "more_body": i < len(chunks) - 1}
                for i, c in enumerate(chunks)
            ]
        )
        sent: list[dict[str, Any]] = []

        async def receive() -> Any:
            return next(messages)

        async def send(message: Any) -> None:
            sent.append(message)

        scope = {"type": "http", "method": "POST", "path": "/", "headers": []}
        await BodySizeLimitMiddleware(app, max_bytes=limit)(scope, receive, send)
        return sent

    def test_rejects_when_stream_exceeds_limit(self) -> None:
        sent = asyncio.run(self._run([b"a" * 600, b"b" * 600], limit=1000))
        assert sent[0]["status"] == 413

    def test_passes_small_streams(self) -> None:
        sent = asyncio.run(self._run([b"a" * 300, b"b" * 300], limit=1000))
        assert sent[0]["status"] == 200


class TestHelpers:
    @pytest.mark.parametrize(
        ("original", "expected"),
        [
            ("contract.pdf", "signed_contract.pdf"),
            (r"C:\Users\me\Desktop\deal.PDF", "signed_deal.PDF"),
            ("../../etc/passwd", "signed_passwd.pdf"),
            ("bad\r\nname.pdf", "signed_badname.pdf"),
            (None, "signed_document.pdf"),
            ("...", "signed_document.pdf"),
        ],
    )
    def test_download_name(self, original: str | None, expected: str) -> None:
        assert download_name(original) == expected

    def test_content_disposition_is_header_safe(self) -> None:
        header = content_disposition('signed_"x";\u0639.pdf')
        assert header.startswith("attachment; filename=\"signed__x___.pdf\"; filename*=UTF-8''")
        assert header.isascii()

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("LocalHost:8765", "localhost"),
            ("[::1]:8765", "::1"),
            ("127.0.0.1", "127.0.0.1"),
            ("[::1", "[::1"),
        ],
    )
    def test_host_without_port(self, raw: str, expected: str) -> None:
        assert host_without_port(raw) == expected

"""Builds the real FastAPI app around fake ports (shared by API and desktop tests)."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from sigil.api import create_app
from sigil.application.signing_service import SigningService
from sigil.application.token_service import TokenService
from sigil.container import Container
from sigil.infrastructure.config import AgentSettings
from tests.support.fakes import (
    NOW,
    FakeGateway,
    RecordingAuditLog,
    RecordingCmsEngine,
    RecordingPdfEngine,
    cert_info,
)

WEB_APP = "https://erp.example.com"


class Harness:
    """Builds an app around fakes and exposes them for assertions."""

    def __init__(self, timestamps: bool = False, **settings: Any) -> None:
        self.gateway = FakeGateway(certificates=[cert_info("ca", is_ca=True), cert_info("01")])
        self.pdf_engine = RecordingPdfEngine()
        self.cms_engine = RecordingCmsEngine()
        self.audit = RecordingAuditLog()
        self.settings = AgentSettings(allowed_origins=(WEB_APP,), **settings)
        container = Container(
            settings=self.settings,
            token_service=TokenService(self.gateway),
            signing_service=SigningService(
                self.gateway, self.pdf_engine, self.cms_engine, self.audit, clock=lambda: NOW
            ),
            timestamps_available=timestamps,
        )
        self.client = TestClient(
            create_app(container), base_url="http://127.0.0.1:8765", raise_server_exceptions=False
        )

"""FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI

from sigil import __version__
from sigil.container import Container

from .errors import install_error_handlers
from .routes import router
from .security import install_security

DESCRIPTION = """
Local bridge between your web system and a PKCS#11 hard token.

* Errors always have the shape `{"error": {"code", "message", "details"}}` — switch on `code`.
* Only allow-listed web origins may call the agent; configure `allowed_origins`.
* The PIN is sent per request, used once for the token login and never stored or logged.
"""


def create_app(container: Container) -> FastAPI:
    """Build the HTTP application around an already wired :class:`Container`."""
    settings = container.settings
    app = FastAPI(
        title="Sigil",
        version=__version__,
        description=DESCRIPTION,
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )
    app.state.container = container
    install_error_handlers(app)
    app.include_router(router)
    install_security(app, settings)
    return app

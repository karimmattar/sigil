"""Uniform JSON error responses: ``{"error": {"code", "message", "details"}}``.

* Domain errors (:class:`AgentError`) → their stable ``code`` + mapped HTTP status.
* Request validation errors → ``VALIDATION_ERROR``; the offending *input values are not
  echoed back* (they could contain the PIN).
* Anything unexpected → ``INTERNAL_ERROR`` with a correlation id; details go to the log only.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Mapping

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sigil.domain import errors as e

logger = logging.getLogger(__name__)

#: HTTP status per domain error class (looked up along the MRO, so subclasses inherit).
STATUS_BY_ERROR: Mapping[type[e.AgentError], int] = {
    e.DriverNotFoundError: 503,
    e.DriverLoadError: 503,
    e.TokenNotFoundError: 404,
    e.CertificateNotFoundError: 404,
    e.TokenAmbiguousError: 409,
    e.CertificateAmbiguousError: 409,
    e.CertificateNotUsableError: 409,
    e.TokenBusyError: 409,
    e.TokenRemovedError: 409,
    e.FieldAlreadySignedError: 409,
    e.PinIncorrectError: 401,
    e.PinLockedError: 423,
    e.PinInvalidError: 422,
    e.InvalidRequestError: 422,
    e.InvalidDocumentError: 422,
    e.PayloadTooLargeError: 413,
    e.TimestampError: 502,
    e.SigningError: 500,
}


def status_for(error: e.AgentError) -> int:
    for cls in type(error).__mro__:
        if cls in STATUS_BY_ERROR:
            return STATUS_BY_ERROR[cls]
    return 500


def error_response(
    status: int, code: str, message: str, details: Mapping[str, object] | None = None
) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "details": dict(details or {})}},
    )


def internal_error_response() -> JSONResponse:
    correlation_id = uuid.uuid4().hex[:12]
    logger.exception("Unhandled error (correlation id %s)", correlation_id)
    return error_response(
        500,
        "INTERNAL_ERROR",
        "Unexpected error inside Sigil. See the agent log for details.",
        {"correlation_id": correlation_id},
    )


async def _agent_error(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, e.AgentError)
    status = status_for(exc)
    log = logger.warning if status >= 500 else logger.info
    log("%s %s: %s", status, exc.code, exc.message)
    return error_response(status, exc.code, exc.message, exc.details)


async def _validation_error(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    problems = [
        {
            "field": ".".join(str(p) for p in err.get("loc", ()) if p != "body"),
            "message": err.get("msg"),
        }
        for err in exc.errors()
    ]
    return error_response(422, "VALIDATION_ERROR", "The request is invalid.", {"errors": problems})


async def _http_error(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, StarletteHTTPException)
    code = {404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED"}.get(exc.status_code, "HTTP_ERROR")
    response = error_response(exc.status_code, code, str(exc.detail))
    if exc.headers:
        response.headers.update(exc.headers)
    return response


def install_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(e.AgentError, _agent_error)
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.add_exception_handler(StarletteHTTPException, _http_error)


class UnhandledErrorMiddleware:
    """Innermost middleware turning unexpected exceptions into JSON 500 responses.

    Starlette's own catch-all sits *outside* every user middleware, so its responses
    would miss the CORS headers and the web system could not read the error.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = False

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception:
            if started:
                raise
            await internal_error_response()(scope, receive, send)

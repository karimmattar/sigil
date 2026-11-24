"""Security middleware for a local agent that browsers talk to.

Threat model: the agent listens on the user's machine; *every* website the user visits
can make the browser send requests to ``http://127.0.0.1:<port>``. CORS alone does not
stop that — it only hides responses, and ``multipart/form-data`` POSTs are "simple"
requests that are sent without a preflight. So the agent itself must refuse:

* :class:`HostGuardMiddleware` — requests whose ``Host`` is not loopback (DNS rebinding);
* :class:`OriginGuardMiddleware` — browser requests from origins that are not allow-listed
  (stops CSRF and PIN brute-forcing that could lock the token);
* :class:`BodySizeLimitMiddleware` — oversized uploads (memory exhaustion);
* :class:`SecurityHeadersMiddleware` — ``nosniff``, ``no-store``, framing protection.

Requests *without* an ``Origin`` header come from non-browser local programs, which
already run with the user's privileges, so they are allowed.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable

from fastapi import FastAPI
from starlette.datastructures import Headers, MutableHeaders
from starlette.middleware.cors import CORSMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sigil.infrastructure.config import AgentSettings, normalize_origin

from .errors import UnhandledErrorMiddleware, error_response

logger = logging.getLogger(__name__)

EXPOSED_HEADERS = (
    "Content-Disposition",
    "X-Signature-Field",
    "X-Signer-Certificate-Id",
    "X-Token-Serial",
)


def host_without_port(host_header: str) -> str:
    """``'[::1]:8765'`` → ``'::1'``, ``'LocalHost:8765'`` → ``'localhost'``."""
    host = host_header.strip().lower()
    if host.startswith("["):
        return host[1 : host.find("]")] if "]" in host else host
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def self_origins(port: int) -> set[str]:
    """Origins of pages served by the agent itself (e.g. the /docs "Try it out" button)."""
    return {
        f"{scheme}://{host}:{port}"
        for scheme in ("http", "https")
        for host in ("127.0.0.1", "localhost", "[::1]")
    }


class HostGuardMiddleware:
    """Reject requests whose ``Host`` header is not one of ``allowed_hosts``."""

    def __init__(self, app: ASGIApp, allowed_hosts: Iterable[str]) -> None:
        self.app = app
        self.allowed = frozenset(allowed_hosts)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            host = host_without_port(Headers(scope=scope).get("host", ""))
            if host not in self.allowed:
                logger.warning("Rejected request with Host '%s'", host)
                response = error_response(
                    403, "HOST_NOT_ALLOWED", "Requests must target localhost."
                )
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


class OriginGuardMiddleware:
    """Reject browser requests from origins that are not allow-listed (before routing)."""

    def __init__(self, app: ASGIApp, allowed_origins: Iterable[str]) -> None:
        self.app = app
        self.allowed = frozenset(allowed_origins)

    def is_allowed(self, origin: str) -> bool:
        try:
            return normalize_origin(origin) in self.allowed
        except ValueError:  # "null", malformed, non-http(s)
            return False

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            origin = Headers(scope=scope).get("origin")
            if origin is not None and not self.is_allowed(origin):
                logger.warning("Rejected request from origin '%s'", origin)
                response = error_response(
                    403,
                    "ORIGIN_NOT_ALLOWED",
                    "This website is not allowed to use Sigil.",
                    {"origin": origin},
                )
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


class _BodyTooLargeError(Exception):
    pass


class BodySizeLimitMiddleware:
    """Refuse request bodies larger than ``max_bytes`` (checks Content-Length and streams)."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = Headers(scope=scope).get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.max_bytes:
            await self._reject(scope, receive, send)
            return

        received = 0
        started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _BodyTooLargeError
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            started = started or message["type"] == "http.response.start"
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _BodyTooLargeError:
            if started:
                raise
            await self._reject(scope, receive, send)

    async def _reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        limit_mb = self.max_bytes // (1024 * 1024)
        response = error_response(
            413,
            "PAYLOAD_TOO_LARGE",
            f"The request is larger than the configured limit of {limit_mb} MB.",
            {"max_bytes": self.max_bytes},
        )
        await response(scope, receive, send)


class SecurityHeadersMiddleware:
    """Add defensive headers to every response."""

    HEADERS: tuple[tuple[str, str], ...] = (
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("Cache-Control", "no-store"),
    )

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in self.HEADERS:
                    headers.setdefault(name, value)
            await send(message)

        await self.app(scope, receive, send_with_headers)


def install_security(app: FastAPI, settings: AgentSettings) -> None:
    """Install the middleware stack. ``add_middleware`` wraps, so the LAST added runs FIRST.

    Request flow: Host guard → Origin guard → CORS (incl. Chrome's Private Network Access
    preflight) → size limit → headers → catch-all → routes.
    """
    origins = sorted(set(settings.allowed_origins) | self_origins(settings.port))
    app.add_middleware(UnhandledErrorMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_upload_bytes)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=list(EXPOSED_HEADERS),
        allow_credentials=False,
        # Chrome asks before a public HTTPS page may call a loopback address. Only
        # allow-listed origins get this far (the origin guard runs first).
        allow_private_network=True,
        max_age=600,
    )
    app.add_middleware(OriginGuardMiddleware, allowed_origins=origins)
    app.add_middleware(HostGuardMiddleware, allowed_hosts=settings.allowed_hosts)

"""HTTP API (FastAPI): thin adapters between JSON/multipart and the application services."""

from .app import create_app

__all__ = ["create_app"]

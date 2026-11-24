"""Agent settings.

Precedence (lowest → highest):

1. defaults in :class:`AgentSettings`
2. TOML config file (``sigil config path`` shows where; ``SIGIL_CONFIG`` overrides)
3. environment variables ``SIGIL_<FIELD>`` (lists are comma-separated)
4. legacy ``PKCS11_LIB_PATH`` (from the original agent) if ``pkcs11_module`` is still unset
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .paths import default_config_file

ENV_PREFIX = "SIGIL_"
LEGACY_MODULE_ENV = "PKCS11_LIB_PATH"
CONFIG_PATH_ENV = "SIGIL_CONFIG"

_LIST_FIELDS = frozenset({"allowed_origins", "allowed_hosts", "extra_module_paths"})
_DEFAULT_PORTS = {"http": 80, "https": 443}
_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


class ConfigError(Exception):
    """The configuration file or environment contains invalid values."""


def normalize_origin(origin: str) -> str:
    """Canonical ``scheme://host[:port]`` form, as browsers send it in the ``Origin`` header."""
    parts = urlsplit(origin.strip())
    if parts.scheme not in _DEFAULT_PORTS or not parts.hostname:
        raise ValueError(f"'{origin}' is not an http(s) origin such as https://erp.example.com")
    if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username:
        raise ValueError(f"origin '{origin}' must not contain a path, query or credentials")
    host = parts.hostname.lower()
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    port = parts.port
    if port is None or port == _DEFAULT_PORTS[parts.scheme]:
        return f"{parts.scheme}://{host}"
    return f"{parts.scheme}://{host}:{port}"


class AgentSettings(BaseModel):
    """Validated, immutable runtime settings."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    # --- network -------------------------------------------------------------------------
    host: str = "127.0.0.1"
    port: int = Field(8765, ge=1, le=65535)
    allowed_origins: tuple[str, ...] = ("http://localhost:3000",)
    allowed_hosts: tuple[str, ...] = _LOOPBACK_HOSTS
    ssl_certfile: Path | None = None
    ssl_keyfile: Path | None = None
    enable_docs: bool = True

    # --- token driver --------------------------------------------------------------------
    pkcs11_module: Path | None = None
    extra_module_paths: tuple[Path, ...] = ()
    token_lock_timeout_seconds: float = Field(30.0, gt=0, le=600)

    # --- signing -------------------------------------------------------------------------
    max_upload_mb: int = Field(50, ge=1, le=1024)
    tsa_url: str | None = None
    tsa_timeout_seconds: float = Field(15.0, gt=0, le=120)
    pdf_strict_parsing: bool = False

    # --- desktop -------------------------------------------------------------------------
    tray: bool = True
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_dir: Path | None = None

    @field_validator("allowed_origins")
    @classmethod
    def _check_origins(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if "*" in value:
            raise ValueError(
                "'*' is not allowed: list the exact origin(s) of your web system so other "
                "websites cannot drive the token"
            )
        return tuple(dict.fromkeys(normalize_origin(o) for o in value if o.strip()))

    @field_validator("allowed_hosts")
    @classmethod
    def _check_hosts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(h.strip().lower().strip("[]") for h in value if h.strip()))

    @field_validator("tsa_url")
    @classmethod
    def _check_tsa(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        if urlsplit(value).scheme not in ("http", "https"):
            raise ValueError("tsa_url must be an http(s) URL")
        return value.strip()

    @model_validator(mode="after")
    def _check_tls_pair(self) -> AgentSettings:
        if (self.ssl_certfile is None) != (self.ssl_keyfile is None):
            raise ValueError("ssl_certfile and ssl_keyfile must be set together")
        return self

    # --- derived values ------------------------------------------------------------------
    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024

    @property
    def uses_tls(self) -> bool:
        return self.ssl_certfile is not None

    @property
    def base_url(self) -> str:
        scheme = "https" if self.uses_tls else "http"
        host = "127.0.0.1" if self.host in ("0.0.0.0", "::") else self.host  # noqa: S104
        return f"{scheme}://{host}:{self.port}"

    @property
    def is_loopback_only(self) -> bool:
        return self.host in _LOOPBACK_HOSTS


def _from_env(env: Mapping[str, str]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for name in AgentSettings.model_fields:
        raw = env.get(ENV_PREFIX + name.upper())
        if raw is None:
            continue
        values[name] = (
            [p.strip() for p in raw.split(",") if p.strip()] if name in _LIST_FIELDS else raw
        )
    return values


def resolve_config_path(explicit: Path | None = None, env: Mapping[str, str] | None = None) -> Path:
    """The config file that :func:`load_settings` reads (it may not exist)."""
    env = os.environ if env is None else env
    if explicit is not None:
        return explicit
    if env.get(CONFIG_PATH_ENV):
        return Path(env[CONFIG_PATH_ENV])
    return default_config_file(env=env)


def load_settings(
    config_file: Path | None = None,
    env: Mapping[str, str] | None = None,
    **overrides: Any,
) -> AgentSettings:
    """Build settings from file + environment (+ explicit overrides, e.g. CLI flags)."""
    env = os.environ if env is None else env
    path = resolve_config_path(config_file, env)
    data: dict[str, Any] = {}
    if path.is_file():
        try:
            data.update(tomllib.loads(path.read_text(encoding="utf-8")))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"Cannot read config file {path}: {exc}") from exc
    elif config_file is not None:
        raise ConfigError(f"Config file {path} does not exist")
    data.update(_from_env(env))
    if "pkcs11_module" not in data and env.get(LEGACY_MODULE_ENV):
        data["pkcs11_module"] = env[LEGACY_MODULE_ENV]
    data.update({k: v for k, v in overrides.items() if v is not None})
    try:
        return AgentSettings.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or 'settings'}: {err['msg']}"
            for err in exc.errors()
        )
        raise ConfigError(f"Invalid configuration ({path}): {problems}") from exc


CONFIG_TEMPLATE = """\
# Sigil configuration (TOML).
# Every key is optional; environment variables SIGIL_<KEY> override this file.

# ---- network ---------------------------------------------------------------------------
host = "127.0.0.1"          # keep on loopback unless you know exactly why not
port = 8765
# Exact origin(s) of your web system. Requests from any other website are rejected.
allowed_origins = ["http://localhost:3000"]
allowed_hosts = ["127.0.0.1", "localhost", "::1"]
enable_docs = true          # interactive API docs at /docs
# HTTPS for browsers that refuse http://127.0.0.1 from HTTPS pages (e.g. certificates from mkcert):
# ssl_certfile = "/path/to/127.0.0.1.pem"
# ssl_keyfile = "/path/to/127.0.0.1-key.pem"

# ---- token driver ----------------------------------------------------------------------
# Leave unset to auto-detect (ePass2003 / Egypt Trust, SafeNet, WatchData, OpenSC, ...).
# pkcs11_module = "C:/Windows/System32/eps2003csp11.dll"
extra_module_paths = []
token_lock_timeout_seconds = 30

# ---- signing ---------------------------------------------------------------------------
max_upload_mb = 50
# RFC 3161 time-stamping authority; when set, signatures are time-stamped by default.
# tsa_url = "http://timestamp.digicert.com"
tsa_timeout_seconds = 15
# false = also accept PDFs with hybrid cross-reference tables (e.g. some MS Word exports).
pdf_strict_parsing = false

# ---- desktop ---------------------------------------------------------------------------
tray = true
log_level = "INFO"
# log_dir = "/custom/log/dir"
"""


def write_config_template(path: Path, *, overwrite: bool = False) -> Path:
    """Write :data:`CONFIG_TEMPLATE` to ``path`` (refuses to overwrite unless asked)."""
    if path.exists() and not overwrite:
        raise ConfigError(f"{path} already exists (use --force to overwrite)")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(CONFIG_TEMPLATE, encoding="utf-8")
    return path

"""The single, process-wide PKCS#11 module instance.

Why this class exists:

* **Serialisation** (audit finding #3 of the original agent). python-pkcs11 initialises
  the driver with ``C_Initialize(NULL)``, which per the PKCS#11 spec gives *no*
  multi-threading guarantees, and a token's login state is shared by all of its sessions.
  Every PKCS#11 call therefore runs under one lock (:meth:`exclusive`); callers that cannot
  get it within ``lock_timeout`` receive ``TOKEN_BUSY`` instead of hanging or colliding.
* **One owner for the driver.** The loaded library, the path it came from and the last
  load error live in one place, so health checks can report them and device errors can
  trigger a re-initialisation (:meth:`invalidate`).
* **Lazy, retryable loading.** Installing the driver while the agent is already running
  works without a restart.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

from sigil.domain.errors import (
    AgentError,
    DriverLoadError,
    DriverNotFoundError,
    TokenBusyError,
)
from sigil.domain.models import DriverStatus

from .locator import ModuleLocator

logger = logging.getLogger(__name__)

LibraryLoader = Callable[[str], Any]

_STATUS_LOCK_TIMEOUT = 2.0  # health checks must answer quickly even while a signature runs


def _default_loader(path: str) -> Any:
    import pkcs11  # noqa: PLC0415 - keep the C extension out of import time for tooling

    return pkcs11.lib(path)


class Pkcs11Module:
    """Owns the loaded python-pkcs11 ``lib`` object and serialises access to it."""

    def __init__(
        self,
        locator: ModuleLocator,
        *,
        lock_timeout: float = 30.0,
        loader: LibraryLoader | None = None,
    ) -> None:
        self._locator = locator
        self._loader = loader or _default_loader
        self._lock_timeout = lock_timeout
        self._lock = threading.RLock()
        self._lib: Any | None = None
        self._path: str | None = None
        self._last_error: AgentError | None = None

    # ------------------------------------------------------------------ public API

    @contextmanager
    def exclusive(self) -> Iterator[Any]:
        """Hold the driver lock and yield the loaded library object."""
        if not self._lock.acquire(timeout=self._lock_timeout):
            raise TokenBusyError(
                "The token is busy with another request. Please try again in a moment.",
                details={"waited_seconds": self._lock_timeout},
            )
        try:
            yield self._ensure_loaded()
        finally:
            self._lock.release()

    def status(self) -> DriverStatus:
        """Report the driver state without raising (attempts a load if none happened yet)."""
        if self._lib is None and self._lock.acquire(timeout=_STATUS_LOCK_TIMEOUT):
            try:
                self._ensure_loaded()
            except AgentError:
                pass  # recorded in self._last_error
            finally:
                self._lock.release()
        lib = self._lib
        if lib is not None:
            major, minor = lib.library_version
            return DriverStatus(
                loaded=True,
                module_path=self._path,
                manufacturer=str(lib.manufacturer_id).strip() or None,
                description=str(lib.library_description).strip() or None,
                library_version=f"{major}.{minor}",
                searched=tuple(self._locator.searched_locations()),
            )
        error = self._last_error
        return DriverStatus(
            loaded=False,
            error_code=error.code if error else None,
            error=error.message if error else "Driver not loaded yet (token busy).",
            searched=tuple(self._locator.searched_locations()),
        )

    def invalidate(self) -> None:
        """Re-initialise the driver after a device-level failure (token yanked, reader reset…)."""
        with self._lock:
            if self._lib is None:
                return
            try:
                self._lib.reinitialize()
                logger.info("PKCS#11 module re-initialised after a device error")
            except Exception as exc:  # driver in a bad state: drop it, reload on next use
                logger.warning("Re-initialising the PKCS#11 module failed (%s); will reload", exc)
                self._lib = None
                self._path = None

    # ------------------------------------------------------------------ internals

    def _ensure_loaded(self) -> Any:
        if self._lib is not None:
            return self._lib
        try:
            self._lib = self._load()
            self._last_error = None
            return self._lib
        except AgentError as exc:
            self._last_error = exc
            raise

    def _load(self) -> Any:
        candidates = self._locator.candidates()
        if not candidates:
            explicit = self._locator.explicit
            message = (
                f"The configured PKCS#11 module '{explicit}' does not exist."
                if explicit is not None
                else "No hard-token driver (PKCS#11 module) was found. Install your token's "
                "driver (e.g. ePass2003 / Egypt Trust) or set pkcs11_module in the config."
            )
            raise DriverNotFoundError(
                message, details={"searched": self._locator.searched_locations()}
            )

        errors: dict[str, str] = {}
        for path in candidates:
            try:
                lib = self._loader(path)
            except Exception as exc:  # any loader failure means "try the next candidate"
                errors[path] = f"{type(exc).__name__}: {exc}"
                logger.warning("Cannot load PKCS#11 module %s: %s", path, exc)
                continue
            self._path = path
            logger.info("Loaded PKCS#11 module %s", path)
            return lib

        raise DriverLoadError(
            "A token driver was found but could not be loaded. Make sure it matches this "
            "agent's architecture (64/32-bit, Intel/ARM) and is installed correctly.",
            details={"errors": errors},
        )

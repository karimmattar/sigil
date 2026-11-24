"""Domain layer: the signing vocabulary (value objects, errors, policies, ports).

Rules for this package:
  * pure Python only — no I/O, no FastAPI, no python-pkcs11, no pyHanko;
  * everything is immutable so it can be shared across threads;
  * infrastructure adapters implement the protocols declared in :mod:`.ports`.
"""

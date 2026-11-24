"""Shared fixtures."""

from __future__ import annotations

import pytest

from tests.support.pki import TestPki


@pytest.fixture(scope="session")
def pki() -> TestPki:
    """One throw-away PKI per test session (RSA key generation is slow)."""
    return TestPki.create()

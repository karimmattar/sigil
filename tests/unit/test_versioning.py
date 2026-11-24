"""Version and fruit-codename rules (see docs/RELEASING.md)."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from sigil import CODENAMES, __codename__, __version__, display_version

ROOT = Path(__file__).resolve().parents[2]


def test_version_is_semver() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?", __version__)


def test_codename_comes_from_the_fruit_sequence() -> None:
    assert __codename__ in CODENAMES


def test_codenames_are_unique_and_alphabetical() -> None:
    assert len(set(CODENAMES)) == len(CODENAMES)
    assert list(CODENAMES) == sorted(CODENAMES)


def test_minor_versions_of_1_x_follow_the_sequence() -> None:
    """1.0 = Apricot, 1.1 = Banana, … — update this rule when 2.0 arrives."""
    major, minor = (int(part) for part in __version__.split(".")[:2])
    if major == 1:
        assert CODENAMES.index(__codename__) == minor


def test_display_version() -> None:
    assert display_version() == f'{__version__} "{__codename__}"'


def test_package_metadata_reads_the_single_version_source() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert "version" in pyproject["project"]["dynamic"]
    assert pyproject["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "sigil.__version__"}


def test_changelog_documents_the_current_version() -> None:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## {__version__} " in changelog
    assert __codename__ in changelog

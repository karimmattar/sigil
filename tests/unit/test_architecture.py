"""Enforce the dependency rule of the layered (hexagonal) architecture.

domain        → standard library only
application   → domain (+ standard library)
Frameworks (FastAPI, python-pkcs11, pyHanko, …) may only appear in outer layers.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[2] / "src" / "sigil"
FRAMEWORKS = {
    "fastapi",
    "starlette",
    "pydantic",
    "uvicorn",
    "pkcs11",
    "pyhanko",
    "pyhanko_certvalidator",
    "asn1crypto",
    "cryptography",
    "pystray",
    "PIL",
}
OUTER_LAYERS = {
    "sigil.infrastructure",
    "sigil.api",
    "sigil.desktop",
    "sigil.container",
}


def imported_modules(path: Path) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            modules.add(node.module)
    return modules


def violations(layer: str, forbidden_internal: set[str]) -> list[str]:
    found = []
    for path in sorted((PACKAGE / layer).rglob("*.py")):
        for module in imported_modules(path):
            top = module.split(".")[0]
            if top in FRAMEWORKS or any(module.startswith(f) for f in forbidden_internal):
                found.append(f"{path.relative_to(PACKAGE)} imports {module}")
    return found


@pytest.mark.parametrize(
    ("layer", "forbidden"),
    [
        ("domain", OUTER_LAYERS | {"sigil.application"}),
        ("application", OUTER_LAYERS),
    ],
)
def test_inner_layers_do_not_depend_on_outer_layers(layer: str, forbidden: set[str]) -> None:
    assert violations(layer, forbidden) == []

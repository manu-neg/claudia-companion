"""Dependency rule for the framework-free packages: domain, application, events, ports, wire.

CLAUDE.md: the core is stdlib + other core modules only, so the notifier
logic (ADR 0021) stays testable with fakes and portable across channels.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import preview_dashboard

pytestmark = pytest.mark.unit

ROOT = Path(preview_dashboard.__file__).parent
CORE = ("domain", "application", "events", "ports", "wire")
FORBIDDEN = {
    "fastapi",
    "starlette",
    "uvicorn",
    "httpx",
    "httpcore",
    "sqlite3",
    "mcp",
    "pydantic",
    "pydantic_settings",
    "anyio",
    "requests",
    "telegram",
}
# The core may not reach outward into these layers either.
FORBIDDEN_INTERNAL = ("preview_dashboard.adapters", "preview_dashboard.interfaces")
FORBIDDEN_INTERNAL_MODULES = ("preview_dashboard.bootstrap", "preview_dashboard.config")


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


@pytest.mark.parametrize(
    "path",
    sorted(p for pkg in CORE for p in (ROOT / pkg).rglob("*.py")),
    ids=lambda p: str(p.relative_to(ROOT)),
)
def test_core_module_imports_no_framework(path: Path) -> None:
    for name in _imports(path):
        assert name.split(".")[0] not in FORBIDDEN, f"{path.name} imports {name}"
        assert not name.startswith(FORBIDDEN_INTERNAL), f"{path.name} imports {name}"
        assert name not in FORBIDDEN_INTERNAL_MODULES, f"{path.name} imports {name}"


@pytest.mark.parametrize(
    "path",
    sorted((ROOT / "adapters").rglob("*.py")),
    ids=lambda p: str(p.relative_to(ROOT)),
)
def test_adapters_never_import_interfaces(path: Path) -> None:
    # Shared protocols live in `wire/` (e.g. the notifier wire format), so an
    # adapter never depends on an interface layer.
    for name in _imports(path):
        assert not name.startswith("preview_dashboard.interfaces"), f"{path.name} imports {name}"

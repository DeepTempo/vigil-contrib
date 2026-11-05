"""The API refuses to start when any router fails to import, so a moved name fails here first."""

import pytest

from services.api.discovery import iter_router_modules, load_router_specs

pytestmark = pytest.mark.unit


def test_every_discovered_router_imports_and_declares_its_mount():
    specs = load_router_specs()
    assert [name for name, _, _ in specs] == iter_router_modules()
    assert "detection_engineering" in iter_router_modules()

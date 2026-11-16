"""``GET /openapi.json`` through the real app, so ``/docs`` renders.

FastAPI builds each route's response model from its return annotation. A
route annotated ``-> Response`` whose ``Response`` import only exists under
``TYPE_CHECKING`` leaves an unresolved forward reference, and schema
generation then raises ``PydanticUserError`` (HTTP 500).
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import TYPE_CHECKING

from fastapi import APIRouter
from fastapi.routing import APIRoute

import af_mcp_broker.api as api_package

if TYPE_CHECKING:
    from fastapi.testclient import TestClient


def _declared_v1_paths() -> set[str]:
    """Every route declared on an ``api/`` module's router, under the ``/v1`` prefix ``api/router.py`` mounts them at."""
    paths: set[str] = set()
    for module_info in pkgutil.iter_modules(api_package.__path__):
        # Mounted on the app directly, not under /v1.
        if module_info.name == "wellknown":
            continue
        module = importlib.import_module(f"{api_package.__name__}.{module_info.name}")
        for value in vars(module).values():
            if isinstance(value, APIRouter):
                paths.update(
                    f"/v1{route.path}"
                    for route in value.routes
                    if isinstance(route, APIRoute)
                )
    return paths


def test_openapi_json_renders_and_lists_every_v1_route(
    app_client: tuple[TestClient, dict],
) -> None:
    client, _state = app_client

    resp = client.get("/openapi.json")

    assert resp.status_code == 200
    declared = _declared_v1_paths()
    assert declared  # guards the enumeration itself
    assert declared <= resp.json()["paths"].keys()

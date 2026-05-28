"""Reads the live RouteRegistry and discovers runbook classes."""
from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import Any

import tengen.routing.routes.cloud.aws
import tengen.routing.routes.cloud.gcp
import tengen.routing.routes.cloud.azure
import tengen.routing.routes.edr
import tengen.routing.routes.k8s
import tengen.routing.routes.network


def get_routes() -> list[dict[str, Any]]:
    """Return all registered routes from the RouteRegistry."""
    from tengen.routing.registry import registry
    return [
        {"name": r.name, "queue": r.queue, "description": r.description}
        for r in registry.all_routes()
    ]


def get_runbooks() -> list[dict[str, Any]]:
    """Discover runbook classes by inspecting the tengen.runbooks package."""
    from tengen.runbooks.base import BaseRunbook

    discovered = []
    runbook_packages = [
        "tengen.runbooks.cloud.aws",
        "tengen.runbooks.cloud.gcp",
        "tengen.runbooks.cloud.azure",
        "tengen.runbooks.edr",
        "tengen.runbooks.k8s",
    ]
    for pkg_name in runbook_packages:
        try:
            pkg = importlib.import_module(pkg_name)
            for _finder, name, _ispkg in pkgutil.iter_modules(pkg.__path__):  # type: ignore[union-attr]
                mod = importlib.import_module(f"{pkg_name}.{name}")
                for _cls_name, cls in inspect.getmembers(mod, inspect.isclass):
                    if issubclass(cls, BaseRunbook) and cls is not BaseRunbook:
                        discovered.append({
                            "name": getattr(cls, "runbook_name", cls.__name__),
                            "source_queue": getattr(cls, "source_queue", ""),
                            "module": f"{pkg_name}.{name}",
                        })
        except Exception:
            pass
    return discovered

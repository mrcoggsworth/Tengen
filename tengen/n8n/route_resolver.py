"""Hierarchical YAML route resolver for n8n webhook dispatch."""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

import yaml

logger = logging.getLogger(__name__)


class NoRouteError(Exception):
    """No matching route found and no _default fallback exists."""


@dataclass(frozen=True, slots=True)
class RouteMatch:
    """Resolved route to an n8n webhook."""

    webhook_url: str
    route_path: str
    description: str


class RouteResolver:
    """Loads a hierarchical YAML routing spec and resolves vendor/category/event_type to a webhook URL.

    Checks file mtime on each resolve() call and reloads if changed.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._mtime: float = 0.0
        self._routes: dict[str, Any] = {}
        self._load()

    def resolve(self, vendor: str, category: str, event_type: str | None) -> RouteMatch:
        """Walk the route tree from most-specific to least-specific.

        Resolution order:
          1. routes[vendor][category][event_type]  (if event_type given)
          2. routes[vendor][category][_default]
          3. routes[vendor][_default]
          4. routes[_default]

        Raises NoRouteError if nothing matches.
        """
        self._reload_if_changed()

        routes = self._routes

        # Level 1: vendor
        vendor_node = routes.get(vendor)
        if vendor_node and isinstance(vendor_node, dict) and "webhook" not in vendor_node:
            # Level 2: category
            cat_node = vendor_node.get(category)
            if cat_node and isinstance(cat_node, dict) and "webhook" not in cat_node:
                # Level 3: event_type
                if event_type:
                    evt_node = cat_node.get(event_type)
                    if evt_node and isinstance(evt_node, dict) and "webhook" in evt_node:
                        return RouteMatch(
                            webhook_url=evt_node["webhook"],
                            route_path=f"{vendor}.{category}.{event_type}",
                            description=evt_node.get("description", ""),
                        )
                # Category _default
                cat_default = cat_node.get("_default")
                if cat_default and isinstance(cat_default, dict) and "webhook" in cat_default:
                    return RouteMatch(
                        webhook_url=cat_default["webhook"],
                        route_path=f"{vendor}.{category}._default",
                        description=cat_default.get("description", ""),
                    )
            elif cat_node and isinstance(cat_node, dict) and "webhook" in cat_node:
                # Category is a leaf node with webhook
                return RouteMatch(
                    webhook_url=cat_node["webhook"],
                    route_path=f"{vendor}.{category}",
                    description=cat_node.get("description", ""),
                )
            # Vendor _default
            vendor_default = vendor_node.get("_default")
            if vendor_default and isinstance(vendor_default, dict) and "webhook" in vendor_default:
                return RouteMatch(
                    webhook_url=vendor_default["webhook"],
                    route_path=f"{vendor}._default",
                    description=vendor_default.get("description", ""),
                )
        elif vendor_node and isinstance(vendor_node, dict) and "webhook" in vendor_node:
            # Vendor is a leaf node with webhook
            return RouteMatch(
                webhook_url=vendor_node["webhook"],
                route_path=vendor,
                description=vendor_node.get("description", ""),
            )

        # Root _default
        root_default = routes.get("_default")
        if root_default and isinstance(root_default, dict) and "webhook" in root_default:
            return RouteMatch(
                webhook_url=root_default["webhook"],
                route_path="_default",
                description=root_default.get("description", ""),
            )

        raise NoRouteError(f"No route for vendor={vendor}, category={category}, event_type={event_type}")

    def _load(self) -> None:
        with open(self._path) as f:
            data = yaml.safe_load(f)
        self._routes = data.get("routes", {})
        self._mtime = os.path.getmtime(self._path)
        logger.info("Loaded n8n routes from %s (%d top-level entries)", self._path, len(self._routes))

    def _reload_if_changed(self) -> None:
        try:
            current_mtime = os.path.getmtime(self._path)
        except OSError:
            return
        if current_mtime != self._mtime:
            logger.info("Route file changed, reloading: %s", self._path)
            self._load()

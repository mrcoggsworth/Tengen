from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

MatcherFn = Callable[[dict[str, Any]], bool]


@dataclass(frozen=True)
class Route:
    """Immutable descriptor for a single routing destination.

    name:        Dot-separated path, e.g. "cloud.aws.cloudtrail"
    queue:       RabbitMQ queue the router publishes to for this route
    matcher:     Pure function — (raw_payload: dict) -> bool. Must never raise.
    description: Human-readable summary
    """

    name: str
    queue: str
    matcher: MatcherFn
    description: str = ""


class RouteRegistry:
    """Central registry mapping route names to Route objects.

    Routes are matched in registration order (first match wins), so register
    more-specific routes before less-specific ones.
    """

    def __init__(self) -> None:
        self._routes: dict[str, Route] = {}

    def register(self, route: Route) -> None:
        if route.name in self._routes:
            raise ValueError(f"Route '{route.name}' is already registered.")
        self._routes[route.name] = route
        logger.debug("Registered route '%s' -> queue='%s'", route.name, route.queue)

    def match(self, raw_payload: dict[str, Any]) -> Route | None:
        """Return first matching Route, or None (sends to DLQ)."""
        for route in self._routes.values():
            try:
                result = route.matcher(raw_payload)
            except Exception:
                logger.exception("Matcher for route '%s' raised — skipping", route.name)
                result = False
            if result:
                logger.debug("Matched route '%s'", route.name)
                return route
        return None

    def all_routes(self) -> list[Route]:
        return list(self._routes.values())

    def __len__(self) -> int:
        return len(self._routes)

    def __contains__(self, name: object) -> bool:
        return name in self._routes


# Module-level singleton imported by all route files and the Router.
registry: RouteRegistry = RouteRegistry()

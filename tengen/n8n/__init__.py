"""n8n webhook connector package.

Public API:
    RouteResolver, RouteMatch, NoRouteError — route resolution
    N8nClient, N8nRequestFailed — HTTP dispatch
    parse_response — response mapping to EnrichedAlert
"""
from .client import N8nClient, N8nRequestFailed
from .response_parser import parse_response
from .route_resolver import NoRouteError, RouteMatch, RouteResolver

__all__ = [
    "N8nClient",
    "N8nRequestFailed",
    "NoRouteError",
    "RouteMatch",
    "RouteResolver",
    "parse_response",
]

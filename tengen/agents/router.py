"""RouterAgent — routes events to n8n workflows via webhook dispatch."""
from __future__ import annotations

import json
import logging

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

from ..config import settings
from ..n8n.client import N8nClient, N8nRequestFailed
from ..n8n.route_resolver import NoRouteError, RouteResolver

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy singletons – created on first use so tests can set env vars first.
# ---------------------------------------------------------------------------
_route_resolver: RouteResolver | None = None
_n8n_client: N8nClient | None = None


def _get_resolver() -> RouteResolver:
    global _route_resolver
    if _route_resolver is None:
        _route_resolver = RouteResolver(settings.n8n_routes_path)
    return _route_resolver


def _get_client() -> N8nClient:
    global _n8n_client
    if _n8n_client is None:
        _n8n_client = N8nClient(
            timeout=settings.n8n_timeout,
            max_retries=settings.n8n_max_retries,
            backoff_base=settings.n8n_backoff_base,
        )
    return _n8n_client


# ---------------------------------------------------------------------------
# ADK FunctionTool wrappers
# ---------------------------------------------------------------------------

def _resolve_route(vendor: str, category: str, event_type: str | None = None) -> str:
    """Resolve a vendor/category/event_type to an n8n webhook URL.

    Consults the n8n routing spec YAML (auto-reloads on file change).
    Returns JSON: {"webhook_url": "...", "route_path": "...", "description": "..."}.
    On no match: {"error": "no_route", "vendor": "...", "category": "..."}.
    """
    try:
        match = _get_resolver().resolve(vendor, category, event_type)
        return json.dumps({
            "webhook_url": match.webhook_url,
            "route_path": match.route_path,
            "description": match.description,
        })
    except NoRouteError as exc:
        logger.error("No n8n route: %s", exc)
        return json.dumps({
            "error": "no_route",
            "vendor": vendor,
            "category": category,
            "event_type": event_type,
        })


def _execute_webhook(webhook_url: str, payload_json: str) -> str:
    """POST event payload to an n8n webhook and return the response.

    Returns the raw n8n JSON response as a string.
    On failure: {"error": "webhook_failed", "details": "...", "dlq": true}.
    """
    try:
        payload = json.loads(payload_json)
    except json.JSONDecodeError as exc:
        return json.dumps({"error": "invalid_payload", "details": str(exc)})

    try:
        result = _get_client().execute_sync(webhook_url, payload)
        return json.dumps(result)
    except N8nRequestFailed as exc:
        logger.error("n8n webhook failed: %s", exc)
        return json.dumps({
            "error": "webhook_failed",
            "details": str(exc),
            "url": exc.url,
            "status": exc.status,
            "attempts": exc.attempts,
            "dlq": True,
        })


# Expose clean tool names (FunctionTool derives name from __name__).
resolve_route = _resolve_route
resolve_route.__name__ = "resolve_route"  # type: ignore[attr-defined]
resolve_route.__qualname__ = "resolve_route"  # type: ignore[attr-defined]

execute_webhook = _execute_webhook
execute_webhook.__name__ = "execute_webhook"  # type: ignore[attr-defined]
execute_webhook.__qualname__ = "execute_webhook"  # type: ignore[attr-defined]

router_agent = LlmAgent(
    name="router_agent",
    model=settings.model_name,
    description=(
        "Routes security events to the correct n8n workflow via webhook. "
        "Uses a hierarchical routing spec to match vendor/category/event_type "
        "to webhook URLs."
    ),
    instruction=(
        "You are the RouterAgent. You receive a security event or incident as JSON. "
        "Your job is to dispatch it to the correct n8n workflow for processing.\n"
        "\n"
        "1. Analyze the event to identify:\n"
        "   - vendor: the source platform (aws, crowdstrike, gcp, azure, k8s)\n"
        "   - category: the log type or subsystem (cloudtrail, windows, audit, signin)\n"
        "   - event_type: the specific event if identifiable (root_login, powershell_execution)\n"
        "\n"
        "2. Call resolve_route(vendor, category, event_type) to find the n8n webhook URL.\n"
        "   If it returns an error, use the catch-all default or route to DLQ.\n"
        "\n"
        "3. Call execute_webhook(webhook_url, payload_json) with the resolved URL\n"
        "   and the full event JSON as the payload.\n"
        "\n"
        "4. If the webhook succeeds, return the n8n response JSON.\n"
        "   If it fails (dlq=true in response), return the error JSON so the\n"
        "   orchestrator can route to the dead-letter queue.\n"
        "\n"
        "Do not modify the event payload. Pass it to n8n as-is."
    ),
    tools=[
        FunctionTool(func=resolve_route),
        FunctionTool(func=execute_webhook),
    ],
)

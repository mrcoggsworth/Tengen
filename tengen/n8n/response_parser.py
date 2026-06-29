"""Parse freeform n8n webhook responses into EnrichedAlert."""
from __future__ import annotations

import logging
from typing import Any

from tengen.models.alert import Alert
from tengen.models.enriched_alert import EnrichedAlert

logger = logging.getLogger(__name__)

_WELL_KNOWN_FIELDS = ("severity", "recommendations", "iocs", "verdict")


def parse_response(
    raw_response: dict[str, Any] | None,
    original_alert: Alert,
    route_path: str,
) -> EnrichedAlert:
    """Map a freeform n8n JSON response into an EnrichedAlert.

    - Preserves the original alert unchanged.
    - Stuffs the entire n8n response into ``enrichment``.
    - Extracts well-known fields (severity, recommendations, iocs, verdict)
      into ``extracted`` if present.
    - Sets ``enrichment_error=True`` on empty or None responses.
    """
    if not raw_response:
        logger.warning("Empty n8n response for route %s, alert %s", route_path, original_alert.id)
        return EnrichedAlert(
            alert=original_alert,
            runbook=f"n8n.{route_path}",
            enrichment={},
            enrichment_error=True,
            n8n_route_path=route_path,
        )

    extracted: dict[str, Any] = {}
    for key in _WELL_KNOWN_FIELDS:
        if key in raw_response:
            extracted[key] = raw_response[key]

    return EnrichedAlert(
        alert=original_alert,
        runbook=f"n8n.{route_path}",
        enrichment=raw_response,
        extracted=extracted,
        enrichment_error=False,
        n8n_route_path=route_path,
    )

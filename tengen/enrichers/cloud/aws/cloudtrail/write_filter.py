"""Stage 1 (parallel): filters principal history to successful write calls."""
from __future__ import annotations

import json
import logging
from typing import Any

from tengen.enrichers.context import EnricherContext

logger = logging.getLogger(__name__)


class WriteCallFilterEnricher:
    name = "write_call_filter"
    cache_ttl: int | None = None
    timeout: float = 1.0

    def run(self, ctx: EnricherContext) -> None:
        try:
            history: list[dict[str, Any]] = (
                ctx.extracted.get("cloudtrail", {}).get("principal_recent_events", [])
            )
            successful_writes = []
            for raw_event in history:
                ct_json = raw_event.get("CloudTrailEvent")
                if not ct_json:
                    continue
                try:
                    event = json.loads(ct_json)
                except (json.JSONDecodeError, TypeError):
                    continue
                if event.get("readOnly") is False and not event.get("errorCode"):
                    successful_writes.append({
                        "eventName": event.get("eventName"),
                        "eventTime": event.get("eventTime"),
                        "eventSource": event.get("eventSource"),
                        "requestParameters": event.get("requestParameters"),
                    })
            ctx.extracted.setdefault("cloudtrail", {})["successful_writes"] = successful_writes
        except Exception as exc:
            ctx.errors.append({"enricher": self.name, "error": str(exc), "type": type(exc).__name__})

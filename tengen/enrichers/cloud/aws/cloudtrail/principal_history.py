"""Stage 1 (parallel): fetches recent CloudTrail events for the principal."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from tengen.enrichers.cache import PrincipalCache
from tengen.enrichers.context import EnricherContext

logger = logging.getLogger(__name__)

_HISTORY_HOURS = 24
_MAX_RESULTS = 20
_CACHE_TTL = 300
_NAMESPACE = "history"


class PrincipalHistoryEnricher:
    name = "principal_history"
    cache_ttl: int | None = _CACHE_TTL
    timeout: float = 5.0

    def __init__(self, cloudtrail_client: Any, cache: PrincipalCache) -> None:
        self._cloudtrail = cloudtrail_client
        self._cache = cache

    def run(self, ctx: EnricherContext) -> None:
        if ctx.principal is None:
            return
        cache_key = ctx.principal.cache_key()
        cached = self._cache.get(cache_key, _NAMESPACE)
        if cached is not None:
            ctx.extracted.setdefault("cloudtrail", {})["principal_recent_events"] = cached
            return
        try:
            end = datetime.now(tz=timezone.utc)
            start = end - timedelta(hours=_HISTORY_HOURS)
            resp = self._cloudtrail.lookup_events(
                LookupAttributes=[
                    {"AttributeKey": "Username", "AttributeValue": ctx.principal.identity}
                ],
                StartTime=start,
                EndTime=end,
                MaxResults=_MAX_RESULTS,
            )
            events = resp.get("Events", [])
            self._cache.set(cache_key, _NAMESPACE, events, _CACHE_TTL)
            ctx.extracted.setdefault("cloudtrail", {})["principal_recent_events"] = events
        except Exception as exc:
            ctx.errors.append({"enricher": self.name, "error": str(exc), "type": type(exc).__name__})

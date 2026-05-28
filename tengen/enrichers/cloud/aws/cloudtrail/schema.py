"""Typed shape for ctx.extracted["cloudtrail"]."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class CloudTrailEnrichment(BaseModel):
    """Aggregated output of the CloudTrail enricher pipeline.

    - principal_recent_events — set by PrincipalHistoryEnricher
    - successful_writes       — set by WriteCallFilterEnricher
    - inspected_objects       — set by ObjectInspectionEnricher
    """

    principal_recent_events: list[dict[str, Any]] = Field(default_factory=list)
    successful_writes: list[dict[str, Any]] = Field(default_factory=list)
    inspected_objects: dict[str, dict[str, Any]] = Field(default_factory=dict)

    model_config = {"frozen": True}

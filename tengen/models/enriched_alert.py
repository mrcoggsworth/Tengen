from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

from .alert import Alert


class EnrichedAlert(BaseModel):
    """Alert after runbook processing.

    Published to the enriched queue for forwarding.
    The original Alert is embedded unchanged so all source fields are preserved.
    """

    alert: Alert
    runbook: str  # dot-separated: "cloud.aws.cloudtrail"
    enriched_at: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    extracted: dict[str, Any] = Field(default_factory=dict)
    runbook_error: str | None = None
    destination: Literal["splunk", "universal", "pagerduty"] = "splunk"

    model_config = {"frozen": True}

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from .alert import AlertSeverity
from .finding import Finding
from .normalized_event import NormalizedEvent


class IncidentStatus(str, Enum):
    OPEN = "open"
    TRIAGING = "triaging"
    CONTAINED = "contained"
    CLOSED = "closed"
    SUPPRESSED = "suppressed"


class Incident(BaseModel):
    """One or more correlated NormalizedEvents grouped into a single case."""

    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    events: list[NormalizedEvent] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    status: IncidentStatus = IncidentStatus.OPEN
    priority_score: float = 0.0
    suppressed: bool = False
    suppression_reason: str = ""
    created_at: str = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )
    updated_at: str = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )
    labels: dict[str, Any] = Field(default_factory=dict)

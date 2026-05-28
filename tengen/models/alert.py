from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class CloudProvider(str, Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    CROWDSTRIKE = "crowdstrike"
    K8S = "k8s"
    OPENSHIFT = "openshift"
    FIREWALL = "firewall"
    UNKNOWN = "unknown"


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Alert(BaseModel):
    """Normalized alert produced by every ingestion consumer.

    Frozen so it cannot be mutated as it flows through the pipeline.
    ``source`` is the transport (kafka, sqs, pubsub, universal, etc.).
    ``raw_payload`` is the original event, untouched.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: str  # transport: "kafka" | "sqs" | "pubsub" | "universal" | custom
    received_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )
    raw_payload: dict[str, Any]
    metadata: dict[str, Any] = Field(default_factory=dict)

    # Legacy fields kept for backwards compat with existing agents/tools
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    severity: AlertSeverity = AlertSeverity.INFO
    event_type: str = ""
    timestamp: str = ""
    account_id: str = ""
    region: str = ""
    project_id: str = ""

    model_config = {"frozen": True}

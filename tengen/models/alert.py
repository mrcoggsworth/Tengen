from enum import Enum
from typing import Any

from pydantic import BaseModel


class CloudProvider(str, Enum):
    AWS = "aws"
    GCP = "gcp"
    UNKNOWN = "unknown"


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Alert(BaseModel):
    alert_id: str
    source: CloudProvider
    severity: AlertSeverity
    event_type: str
    raw_event: dict[str, Any]
    timestamp: str
    account_id: str = ""
    region: str = ""
    project_id: str = ""

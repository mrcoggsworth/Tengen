from typing import Any

from pydantic import BaseModel

from .alert import AlertSeverity, CloudProvider


class RemediationStep(BaseModel):
    order: int
    action: str
    automated: bool = False
    result: str = ""


class Finding(BaseModel):
    finding_id: str
    alert_id: str
    source: CloudProvider
    severity: AlertSeverity
    title: str
    description: str
    remediation_steps: list[RemediationStep] = []
    enrichment: dict[str, Any] = {}
    forwarded: bool = False
    forwarding_targets: list[str] = []

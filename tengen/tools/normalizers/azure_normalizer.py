from __future__ import annotations

from typing import Any

from tengen.models.alert import AlertSeverity
from tengen.models.normalized_event import (
    ActorContext,
    LogSourceType,
    NetworkContext,
    NormalizedEvent,
    Outcome,
    TargetContext,
)


def _infer_severity(event: dict[str, Any]) -> AlertSeverity:
    level = event.get("level", "").upper()
    return {"CRITICAL": AlertSeverity.CRITICAL, "ERROR": AlertSeverity.HIGH, "WARNING": AlertSeverity.MEDIUM}.get(level, AlertSeverity.INFO)


def normalize(raw: dict[str, Any]) -> NormalizedEvent:
    op = raw.get("operationName", {})
    op_value = op.get("value", "") if isinstance(op, dict) else str(op)
    status = raw.get("status", {})
    status_value = status.get("value", "") if isinstance(status, dict) else str(status)

    return NormalizedEvent(
        timestamp=raw.get("eventTimestamp", raw.get("time", "")),
        source_type=LogSourceType.AZURE,
        log_type="azure_activity",
        actor=ActorContext(
            identity=raw.get("caller", ""),
            identity_type="User" if "@" in raw.get("caller", "") else "ServicePrincipal",
            account_id=raw.get("subscriptionId", ""),
        ),
        target=TargetContext(
            resource_name=raw.get("resourceId", ""),
            resource_type=raw.get("resourceProvider", {}).get("value", "") if isinstance(raw.get("resourceProvider"), dict) else raw.get("resourceProvider", ""),
        ),
        network=NetworkContext(
            src_ip=raw.get("httpRequest", {}).get("clientIpAddress", ""),
        ),
        outcome=Outcome.FAILURE if status_value in ("Failed", "Conflict") else Outcome.SUCCESS,
        event_name=op_value,
        severity=_infer_severity(raw),
        raw_event=raw,
        tags=["azure", "activity"],
    )

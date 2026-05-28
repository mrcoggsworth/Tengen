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


def _infer_severity(score: int) -> AlertSeverity:
    if score >= 80:
        return AlertSeverity.CRITICAL
    if score >= 60:
        return AlertSeverity.HIGH
    if score >= 40:
        return AlertSeverity.MEDIUM
    return AlertSeverity.LOW


def normalize(raw: dict[str, Any]) -> NormalizedEvent:
    behaviors = raw.get("Behaviors", [{}])
    first = behaviors[0] if behaviors else {}
    device = raw.get("DeviceDetails", {})
    score = int(raw.get("MaxSeverity", 0))

    return NormalizedEvent(
        timestamp=raw.get("CreatedTimestamp", raw.get("ProcessStartTime", "")),
        source_type=LogSourceType.CROWDSTRIKE,
        log_type="cs_detection",
        actor=ActorContext(
            identity=first.get("UserName", ""),
            identity_type="EndpointUser",
            account_id=raw.get("CustomerIdentifier", ""),
        ),
        target=TargetContext(
            resource_name=device.get("Hostname", raw.get("Hostname", "")),
            resource_type="Endpoint",
        ),
        network=NetworkContext(
            src_ip=raw.get("LocalIP", ""),
            dst_ip=raw.get("ExternalIP", ""),
        ),
        outcome=Outcome.FAILURE,
        event_name=raw.get("DetectName", first.get("Technique", "Detection")),
        severity=_infer_severity(score),
        raw_event=raw,
        tags=["crowdstrike", "edr", first.get("Tactic", "").lower()],
    )

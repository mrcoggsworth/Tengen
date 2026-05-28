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


def normalize(raw: dict[str, Any]) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=raw.get("timestamp", raw.get("time", "")),
        source_type=LogSourceType.FIREWALL,
        log_type=raw.get("log_type", "firewall_deny"),
        actor=ActorContext(identity=raw.get("src_ip", ""), identity_type="NetworkEndpoint"),
        target=TargetContext(
            resource_name=raw.get("dst_ip", ""),
            resource_type="NetworkDestination",
        ),
        network=NetworkContext(
            src_ip=raw.get("src_ip", ""),
            dst_ip=raw.get("dst_ip", ""),
            src_port=raw.get("src_port"),
            dst_port=raw.get("dst_port"),
            protocol=raw.get("protocol", ""),
            bytes_in=raw.get("bytes_in"),
            bytes_out=raw.get("bytes_out"),
        ),
        outcome=Outcome.FAILURE,
        event_name=raw.get("action", "DENY"),
        severity=AlertSeverity.MEDIUM,
        raw_event=raw,
        tags=["firewall", raw.get("interface", "")],
    )

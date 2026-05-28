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
    pps = raw.get("packets_per_second", 0)
    severity = AlertSeverity.CRITICAL if pps > 100000 else (AlertSeverity.HIGH if pps > 10000 else AlertSeverity.MEDIUM)

    return NormalizedEvent(
        timestamp=raw.get("timestamp", raw.get("start_time", "")),
        source_type=LogSourceType.DDOS,
        log_type="ddos_flow",
        actor=ActorContext(
            identity=raw.get("src_ip", raw.get("top_src_ip", "")),
            identity_type="NetworkAttacker",
        ),
        target=TargetContext(
            resource_name=raw.get("dst_ip", raw.get("target_ip", "")),
            resource_type="NetworkTarget",
        ),
        network=NetworkContext(
            src_ip=raw.get("src_ip", ""),
            dst_ip=raw.get("dst_ip", ""),
            dst_port=raw.get("dst_port"),
            protocol=raw.get("protocol", ""),
            bytes_in=raw.get("bytes_received"),
        ),
        outcome=Outcome.FAILURE,
        event_name=raw.get("attack_type", "DDoS"),
        severity=severity,
        raw_event=raw,
        tags=["ddos", raw.get("attack_vector", "volumetric").lower()],
    )

from typing import Any
from tengen.queue.queues import QUEUE_RUNBOOK_CROWDSTRIKE
from tengen.routing.registry import Route, registry


def matches(raw_payload: dict[str, Any]) -> bool:
    return (
        "FalconHostLink" in str(raw_payload.get("Behaviors", ""))
        or raw_payload.get("DetectName") is not None
        or raw_payload.get("event_type") in ("DetectionSummaryEvent", "EppDetectionSummaryEvent")
    )


registry.register(Route(
    name="edr.crowdstrike",
    queue=QUEUE_RUNBOOK_CROWDSTRIKE,
    matcher=matches,
    description="CrowdStrike Falcon detection and alert events",
))

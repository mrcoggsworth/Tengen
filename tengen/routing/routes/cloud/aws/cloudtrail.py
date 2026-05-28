from typing import Any
from tengen.queue.queues import QUEUE_RUNBOOK_CLOUDTRAIL
from tengen.routing.registry import Route, registry


def matches(raw_payload: dict[str, Any]) -> bool:
    event_source = raw_payload.get("eventSource")
    event_version = raw_payload.get("eventVersion")
    return (
        isinstance(event_source, str)
        and event_source.endswith(".amazonaws.com")
        and isinstance(event_version, str)
    )


registry.register(Route(
    name="cloud.aws.cloudtrail",
    queue=QUEUE_RUNBOOK_CLOUDTRAIL,
    matcher=matches,
    description="AWS CloudTrail API activity and console login events",
))

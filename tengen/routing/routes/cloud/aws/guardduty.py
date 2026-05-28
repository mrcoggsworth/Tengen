from typing import Any
from tengen.queue.queues import QUEUE_RUNBOOK_GUARDDUTY
from tengen.routing.registry import Route, registry


def matches(raw_payload: dict[str, Any]) -> bool:
    return (
        raw_payload.get("detail-type") == "GuardDuty Finding"
        and "detail" in raw_payload
        and "type" in raw_payload.get("detail", {})
    )


registry.register(Route(
    name="cloud.aws.guardduty",
    queue=QUEUE_RUNBOOK_GUARDDUTY,
    matcher=matches,
    description="AWS GuardDuty threat detection findings",
))

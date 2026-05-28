from typing import Any
from tengen.queue.queues import QUEUE_RUNBOOK_AZURE_ACTIVITY
from tengen.routing.registry import Route, registry


def matches(raw_payload: dict[str, Any]) -> bool:
    return (
        raw_payload.get("resourceProvider", "").startswith("Microsoft.")
        or "azure" in str(raw_payload.get("tenantId", "")).lower()
        or raw_payload.get("operationName", {}).get("value", "").startswith("Microsoft.")
    )


registry.register(Route(
    name="cloud.azure.activity",
    queue=QUEUE_RUNBOOK_AZURE_ACTIVITY,
    matcher=matches,
    description="Azure Activity Log / ARM audit events",
))

from typing import Any
from tengen.queue.queues import QUEUE_RUNBOOK_GCP_EVENT_AUDIT
from tengen.routing.registry import Route, registry


def matches(raw_payload: dict[str, Any]) -> bool:
    log_name = raw_payload.get("logName", "")
    return "cloudaudit.googleapis.com" in log_name


registry.register(Route(
    name="cloud.gcp.event_audit",
    queue=QUEUE_RUNBOOK_GCP_EVENT_AUDIT,
    matcher=matches,
    description="GCP Cloud Audit Log events (admin activity, data access)",
))

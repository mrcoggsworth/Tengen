from typing import Any
from tengen.queue.queues import QUEUE_RUNBOOK_K8S
from tengen.routing.registry import Route, registry


def matches(raw_payload: dict[str, Any]) -> bool:
    return (
        raw_payload.get("apiVersion") in ("audit.k8s.io/v1", "audit.k8s.io/v1beta1")
        or (
            "requestURI" in raw_payload
            and "userAgent" in raw_payload
            and "objectRef" in raw_payload
        )
    )


registry.register(Route(
    name="k8s.audit",
    queue=QUEUE_RUNBOOK_K8S,
    matcher=matches,
    description="Kubernetes API server audit log events",
))

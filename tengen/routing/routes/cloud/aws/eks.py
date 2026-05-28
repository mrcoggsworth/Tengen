from typing import Any
from tengen.queue.queues import QUEUE_RUNBOOK_EKS
from tengen.routing.registry import Route, registry


def matches(raw_payload: dict[str, Any]) -> bool:
    annotations = raw_payload.get("annotations", {})
    return (
        "kubernetes.io" in str(raw_payload.get("apiVersion", ""))
        or raw_payload.get("sourceIPAddress", "") == "eks.amazonaws.com"
        or bool(annotations.get("eks.amazonaws.com/compute-type"))
    )


registry.register(Route(
    name="cloud.aws.eks",
    queue=QUEUE_RUNBOOK_EKS,
    matcher=matches,
    description="AWS EKS cluster audit events",
))

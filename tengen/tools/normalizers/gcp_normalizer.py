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


def _infer_severity(event: dict[str, Any]) -> AlertSeverity:
    mapping = {"CRITICAL": AlertSeverity.CRITICAL, "ERROR": AlertSeverity.HIGH, "WARNING": AlertSeverity.MEDIUM, "NOTICE": AlertSeverity.LOW}
    return mapping.get(event.get("severity", "").upper(), AlertSeverity.INFO)


def normalize(raw: dict[str, Any]) -> NormalizedEvent:
    proto = raw.get("protoPayload", {})
    auth = proto.get("authenticationInfo", {})
    req_meta = proto.get("requestMetadata", {})
    resource = raw.get("resource", {})
    labels = resource.get("labels", {})

    return NormalizedEvent(
        timestamp=raw.get("timestamp", ""),
        source_type=LogSourceType.GCP,
        log_type="gcp_audit",
        actor=ActorContext(
            identity=auth.get("principalEmail", ""),
            identity_type="ServiceAccount" if ".iam.gserviceaccount.com" in auth.get("principalEmail", "") else "User",
            account_id=labels.get("project_id", ""),
        ),
        target=TargetContext(
            resource_name=proto.get("resourceName", ""),
            resource_type=resource.get("type", ""),
        ),
        network=NetworkContext(
            src_ip=req_meta.get("callerIp", ""),
            user_agent=req_meta.get("callerSuppliedUserAgent", ""),
        ),
        outcome=Outcome.FAILURE if proto.get("status", {}).get("code", 0) != 0 else Outcome.SUCCESS,
        event_name=proto.get("methodName", "Unknown"),
        severity=_infer_severity(raw),
        raw_event=raw,
        tags=["gcp", "audit"],
    )

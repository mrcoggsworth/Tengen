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

_SENSITIVE_RESOURCES = {"secrets", "serviceaccounts", "clusterrolebindings", "rolebindings", "configmaps"}
_PRIVILEGED_VERBS = {"exec", "attach", "portforward", "proxy"}


def _infer_severity(raw: dict[str, Any]) -> AlertSeverity:
    obj_ref = raw.get("objectRef", {})
    resource = obj_ref.get("resource", "")
    verb = raw.get("verb", "")
    if resource in _SENSITIVE_RESOURCES or verb in _PRIVILEGED_VERBS:
        return AlertSeverity.HIGH
    return AlertSeverity.MEDIUM


def normalize(raw: dict[str, Any]) -> NormalizedEvent:
    user = raw.get("user", {})
    obj_ref = raw.get("objectRef", {})
    source_ips = raw.get("sourceIPs", [])
    api_version = raw.get("apiVersion", "")
    source_type = LogSourceType.OPENSHIFT if "openshift.io" in api_version else LogSourceType.K8S

    return NormalizedEvent(
        timestamp=raw.get("requestReceivedTimestamp", raw.get("stageTimestamp", "")),
        source_type=source_type,
        log_type="k8s_audit",
        actor=ActorContext(
            identity=user.get("username", ""),
            identity_type="ServiceAccount" if "system:serviceaccount" in user.get("username", "") else "User",
        ),
        target=TargetContext(
            resource_name=obj_ref.get("name", ""),
            resource_type=obj_ref.get("resource", ""),
            namespace=obj_ref.get("namespace", ""),
        ),
        network=NetworkContext(
            src_ip=source_ips[0] if source_ips else "",
            user_agent=raw.get("userAgent", ""),
        ),
        outcome=Outcome.FAILURE if raw.get("responseStatus", {}).get("code", 0) >= 400 else Outcome.SUCCESS,
        event_name=f"{raw.get('verb', '')} {obj_ref.get('resource', '')}".strip(),
        severity=_infer_severity(raw),
        raw_event=raw,
        tags=["k8s", raw.get("verb", ""), obj_ref.get("namespace", "")],
    )

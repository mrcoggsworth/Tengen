"""Source detection heuristics and normalizer dispatch."""
from __future__ import annotations

from typing import Any

from tengen.models.normalized_event import LogSourceType


def detect_source_type(raw: dict[str, Any]) -> LogSourceType:
    """Heuristically determine the log source type from the raw payload."""
    # AWS CloudTrail
    if raw.get("eventSource", "").endswith(".amazonaws.com") and "eventVersion" in raw:
        return LogSourceType.AWS

    # AWS GuardDuty / EventBridge wrapper
    if raw.get("detail-type") == "GuardDuty Finding":
        return LogSourceType.AWS

    # GCP Audit Log
    if "cloudaudit.googleapis.com" in raw.get("logName", ""):
        return LogSourceType.GCP

    # Azure Activity Log
    resource_provider = raw.get("resourceProvider", {})
    op_name = raw.get("operationName", {})
    if (
        str(resource_provider).startswith("Microsoft.")
        or (isinstance(op_name, dict) and str(op_name.get("value", "")).startswith("Microsoft."))
        or "tenantId" in raw
    ):
        return LogSourceType.AZURE

    # CrowdStrike
    if (
        raw.get("event_type") in ("DetectionSummaryEvent", "EppDetectionSummaryEvent")
        or "FalconHostLink" in str(raw.get("Behaviors", ""))
        or raw.get("DetectName") is not None
    ):
        return LogSourceType.CROWDSTRIKE

    # Kubernetes / OpenShift audit
    if raw.get("apiVersion") in ("audit.k8s.io/v1", "audit.k8s.io/v1beta1"):
        return LogSourceType.K8S
    if "requestURI" in raw and "objectRef" in raw and "userAgent" in raw:
        if raw.get("apiVersion", "").endswith("openshift.io/v1"):
            return LogSourceType.OPENSHIFT
        return LogSourceType.K8S

    # Firewall / DDoS
    if raw.get("action") in ("DENY", "DROP", "BLOCK", "REJECT"):
        return LogSourceType.FIREWALL
    if raw.get("log_type") in ("firewall_deny", "ddos_flow", "pcap_summary"):
        return LogSourceType.DDOS

    return LogSourceType.UNKNOWN


def normalize(raw: dict[str, Any], source_type: LogSourceType | None = None) -> "Any":
    """Detect source type and run the appropriate normalizer."""
    if source_type is None:
        source_type = detect_source_type(raw)

    from tengen.tools.normalizers import (
        aws_normalizer,
        azure_normalizer,
        crowdstrike_normalizer,
        ddos_normalizer,
        firewall_normalizer,
        gcp_normalizer,
        k8s_normalizer,
    )

    dispatch = {
        LogSourceType.AWS: aws_normalizer.normalize,
        LogSourceType.GCP: gcp_normalizer.normalize,
        LogSourceType.AZURE: azure_normalizer.normalize,
        LogSourceType.CROWDSTRIKE: crowdstrike_normalizer.normalize,
        LogSourceType.FIREWALL: firewall_normalizer.normalize,
        LogSourceType.DDOS: ddos_normalizer.normalize,
        LogSourceType.K8S: k8s_normalizer.normalize,
        LogSourceType.OPENSHIFT: k8s_normalizer.normalize,
    }
    normalizer_fn = dispatch.get(source_type, _normalize_unknown)
    return normalizer_fn(raw)


def _normalize_unknown(raw: dict[str, Any]) -> "Any":
    from tengen.models.alert import AlertSeverity
    from tengen.models.normalized_event import NormalizedEvent

    return NormalizedEvent(
        timestamp=raw.get("timestamp", raw.get("eventTime", "")),
        source_type=LogSourceType.UNKNOWN,
        log_type="unknown",
        event_name=raw.get("eventName", raw.get("event_type", "Unknown")),
        severity=AlertSeverity.INFO,
        raw_event=raw,
    )

import uuid

from ..models.alert import Alert, AlertSeverity, CloudProvider


def parse_cloudtrail_event(raw_event: dict) -> Alert:
    return Alert(
        alert_id=str(uuid.uuid4()),
        source=CloudProvider.AWS,
        severity=_infer_aws_severity(raw_event),
        event_type=raw_event.get("eventName", "Unknown"),
        raw_event=raw_event,
        timestamp=raw_event.get("eventTime", ""),
        account_id=raw_event.get("userIdentity", {}).get("accountId", ""),
        region=raw_event.get("awsRegion", ""),
    )


def parse_gcp_audit_event(raw_event: dict) -> Alert:
    return Alert(
        alert_id=str(uuid.uuid4()),
        source=CloudProvider.GCP,
        severity=_infer_gcp_severity(raw_event),
        event_type=raw_event.get("protoPayload", {}).get("methodName", "Unknown"),
        raw_event=raw_event,
        timestamp=raw_event.get("timestamp", ""),
        project_id=raw_event.get("resource", {}).get("labels", {}).get("project_id", ""),
    )


def _infer_aws_severity(event: dict) -> AlertSeverity:
    error_code = event.get("errorCode", "")
    identity_type = event.get("userIdentity", {}).get("type", "")
    if "Root" in identity_type:
        return AlertSeverity.CRITICAL
    if error_code in ("AccessDenied", "UnauthorizedOperation"):
        return AlertSeverity.HIGH
    return AlertSeverity.MEDIUM


def _infer_gcp_severity(event: dict) -> AlertSeverity:
    severity = event.get("severity", "").upper()
    mapping = {
        "CRITICAL": AlertSeverity.CRITICAL,
        "ERROR": AlertSeverity.HIGH,
        "WARNING": AlertSeverity.MEDIUM,
        "NOTICE": AlertSeverity.LOW,
    }
    return mapping.get(severity, AlertSeverity.INFO)

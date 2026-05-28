from __future__ import annotations

import uuid
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
    error_code = event.get("errorCode", "")
    identity_type = event.get("userIdentity", {}).get("type", "")
    if "Root" in identity_type:
        return AlertSeverity.CRITICAL
    if error_code in ("AccessDenied", "UnauthorizedOperation"):
        return AlertSeverity.HIGH
    return AlertSeverity.MEDIUM


def normalize(raw: dict[str, Any]) -> NormalizedEvent:
    identity = raw.get("userIdentity", {})
    arn = identity.get("arn", "")
    account_id = identity.get("accountId", "")
    identity_type = identity.get("type", "Unknown")
    is_privileged = identity_type == "Root" or "admin" in arn.lower()

    resources = raw.get("resources", [])
    first_res = resources[0] if resources else {}

    return NormalizedEvent(
        event_id=raw.get("eventID", str(uuid.uuid4())),
        timestamp=raw.get("eventTime", ""),
        source_type=LogSourceType.AWS,
        log_type="cloudtrail",
        actor=ActorContext(
            identity=arn or identity.get("userName", "unknown"),
            identity_type=identity_type,
            account_id=account_id,
            is_privileged=is_privileged,
        ),
        target=TargetContext(
            resource_name=first_res.get("ARN", first_res.get("resourceName", "")),
            resource_type=first_res.get("type", ""),
            region=raw.get("awsRegion", ""),
        ),
        network=NetworkContext(
            src_ip=raw.get("sourceIPAddress", ""),
            user_agent=raw.get("userAgent", ""),
        ),
        outcome=Outcome.FAILURE if raw.get("errorCode") else Outcome.SUCCESS,
        event_name=raw.get("eventName", "Unknown"),
        severity=_infer_severity(raw),
        raw_event=raw,
        tags=["aws", "cloudtrail"],
    )

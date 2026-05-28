"""GCP Event Audit runbook."""
from __future__ import annotations

import logging
from typing import Any

from tengen.models.alert import Alert
from tengen.models.enriched_alert import EnrichedAlert
from tengen.queue.queues import QUEUE_RUNBOOK_GCP_EVENT_AUDIT
from tengen.runbooks.base import BaseRunbook

logger = logging.getLogger(__name__)


class GcpEventAuditRunbook(BaseRunbook):
    source_queue = QUEUE_RUNBOOK_GCP_EVENT_AUDIT
    runbook_name = "cloud.gcp.event_audit"

    def enrich(self, alert: Alert) -> EnrichedAlert:
        extracted: dict[str, Any] = {}
        runbook_error: str | None = None
        try:
            payload = alert.raw_payload
            proto = payload.get("protoPayload", {})
            auth = proto.get("authenticationInfo", {})
            req_meta = proto.get("requestMetadata", {})
            extracted = {
                "principal_email": auth.get("principalEmail", ""),
                "caller_ip": req_meta.get("callerIp", ""),
                "user_agent": req_meta.get("callerSuppliedUserAgent", ""),
                "service_name": proto.get("serviceName", ""),
                "method_name": proto.get("methodName", ""),
                "resource_name": proto.get("resourceName", ""),
                "authorization_info": proto.get("authorizationInfo", []),
                "severity": payload.get("severity", ""),
                "log_name": payload.get("logName", ""),
            }
        except Exception as exc:
            runbook_error = f"{type(exc).__name__}: {exc}"
            logger.error("GcpEventAuditRunbook enrich() failed for alert %s: %s", alert.id, runbook_error)
        return EnrichedAlert(alert=alert, runbook=self.runbook_name, extracted=extracted, runbook_error=runbook_error)

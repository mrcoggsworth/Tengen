"""Azure Activity Log runbook."""
from __future__ import annotations

import logging
from typing import Any

from tengen.models.alert import Alert
from tengen.models.enriched_alert import EnrichedAlert
from tengen.queue.queues import QUEUE_RUNBOOK_AZURE_ACTIVITY
from tengen.runbooks.base import BaseRunbook

logger = logging.getLogger(__name__)


class AzureActivityRunbook(BaseRunbook):
    source_queue = QUEUE_RUNBOOK_AZURE_ACTIVITY
    runbook_name = "cloud.azure.activity"

    def enrich(self, alert: Alert) -> EnrichedAlert:
        extracted: dict[str, Any] = {}
        runbook_error: str | None = None
        try:
            payload = alert.raw_payload
            caller = payload.get("caller", "")
            op = payload.get("operationName", {})
            extracted = {
                "caller": caller,
                "operation_name": op.get("value", "") if isinstance(op, dict) else str(op),
                "operation_display": op.get("localizedValue", "") if isinstance(op, dict) else "",
                "resource_provider": payload.get("resourceProvider", {}).get("value", ""),
                "resource_id": payload.get("resourceId", ""),
                "subscription_id": payload.get("subscriptionId", ""),
                "tenant_id": payload.get("tenantId", ""),
                "status": payload.get("status", {}).get("value", ""),
                "sub_status": payload.get("subStatus", {}).get("value", ""),
                "event_timestamp": payload.get("eventTimestamp", ""),
                "ip_address": payload.get("httpRequest", {}).get("clientIpAddress", ""),
            }
        except Exception as exc:
            runbook_error = f"{type(exc).__name__}: {exc}"
            logger.error("AzureActivityRunbook enrich() failed for alert %s: %s", alert.id, runbook_error)
        return EnrichedAlert(alert=alert, runbook=self.runbook_name, extracted=extracted, runbook_error=runbook_error)

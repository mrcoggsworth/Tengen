"""Kubernetes / OpenShift audit log runbook."""
from __future__ import annotations

import logging
from typing import Any

from tengen.models.alert import Alert
from tengen.models.enriched_alert import EnrichedAlert
from tengen.queue.queues import QUEUE_RUNBOOK_K8S
from tengen.runbooks.base import BaseRunbook

logger = logging.getLogger(__name__)


class K8sAuditRunbook(BaseRunbook):
    source_queue = QUEUE_RUNBOOK_K8S
    runbook_name = "k8s.audit"

    def enrich(self, alert: Alert) -> EnrichedAlert:
        extracted: dict[str, Any] = {}
        runbook_error: str | None = None
        try:
            payload = alert.raw_payload
            user = payload.get("user", {})
            obj_ref = payload.get("objectRef", {})
            extracted = {
                "verb": payload.get("verb", ""),
                "user": user.get("username", ""),
                "user_groups": user.get("groups", []),
                "source_ips": payload.get("sourceIPs", []),
                "user_agent": payload.get("userAgent", ""),
                "namespace": obj_ref.get("namespace", ""),
                "resource": obj_ref.get("resource", ""),
                "subresource": obj_ref.get("subresource", ""),
                "name": obj_ref.get("name", ""),
                "api_version": obj_ref.get("apiVersion", ""),
                "response_status": payload.get("responseStatus", {}).get("code", 0),
                "request_uri": payload.get("requestURI", ""),
                "annotations": payload.get("annotations", {}),
            }
            # Flag privileged operations
            sensitive = (
                obj_ref.get("resource") in ("secrets", "serviceaccounts", "clusterrolebindings", "rolebindings")
                or payload.get("verb") in ("exec", "attach", "portforward")
            )
            extracted["is_sensitive_operation"] = sensitive
        except Exception as exc:
            runbook_error = f"{type(exc).__name__}: {exc}"
            logger.error("K8sAuditRunbook enrich() failed for alert %s: %s", alert.id, runbook_error)
        return EnrichedAlert(alert=alert, runbook=self.runbook_name, extracted=extracted, runbook_error=runbook_error)

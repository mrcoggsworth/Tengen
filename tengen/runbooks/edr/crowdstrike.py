"""CrowdStrike Falcon detection runbook."""
from __future__ import annotations

import logging
from typing import Any

from tengen.models.alert import Alert
from tengen.models.enriched_alert import EnrichedAlert
from tengen.queue.queues import QUEUE_RUNBOOK_CROWDSTRIKE
from tengen.runbooks.base import BaseRunbook

logger = logging.getLogger(__name__)


class CrowdStrikeRunbook(BaseRunbook):
    source_queue = QUEUE_RUNBOOK_CROWDSTRIKE
    runbook_name = "edr.crowdstrike"

    def enrich(self, alert: Alert) -> EnrichedAlert:
        extracted: dict[str, Any] = {}
        runbook_error: str | None = None
        try:
            payload = alert.raw_payload
            behaviors = payload.get("Behaviors", [{}])
            first = behaviors[0] if behaviors else {}
            extracted = {
                "detect_name": payload.get("DetectName", ""),
                "detect_description": payload.get("DetectDescription", ""),
                "severity": payload.get("MaxSeverityDisplayName", ""),
                "severity_score": payload.get("MaxSeverity", 0),
                "status": payload.get("Status", ""),
                "host_info": payload.get("DeviceDetails", {}),
                "tactic": first.get("Tactic", ""),
                "technique": first.get("Technique", ""),
                "objective": first.get("Objective", ""),
                "user_name": first.get("UserName", ""),
                "parent_process": first.get("ParentDetails", {}).get("filename", ""),
                "process_name": first.get("FileName", ""),
                "command_line": first.get("CmdLine", ""),
                "sha256": first.get("SHA256String", ""),
                "local_ip": payload.get("LocalIP", ""),
                "external_ip": payload.get("ExternalIP", ""),
                "falcon_host_link": payload.get("FalconHostLink", ""),
            }
        except Exception as exc:
            runbook_error = f"{type(exc).__name__}: {exc}"
            logger.error("CrowdStrikeRunbook enrich() failed for alert %s: %s", alert.id, runbook_error)
        return EnrichedAlert(alert=alert, runbook=self.runbook_name, extracted=extracted, runbook_error=runbook_error)

"""AzureRunbookAgent — investigates Azure Activity Log security events."""
from __future__ import annotations

import json

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

from ..config import settings
from ..tools.runbook_loader import list_runbooks, load_runbook


def _list_azure_runbooks() -> str:
    """List all available Azure runbooks."""
    runbooks = list_runbooks("azure")
    return ", ".join(runbooks) if runbooks else "no runbooks found"


def _load_azure_runbook(event_type: str) -> str:
    """Load a specific Azure runbook by event type slug."""
    runbook = load_runbook("azure", event_type)
    if runbook is None:
        return f"no runbook found for event_type={event_type}"
    return runbook.model_dump_json()


def _enrich_azure_event(normalized_event_json: str) -> str:
    """Extract key fields from a normalized Azure Activity Log event."""
    try:
        event = json.loads(normalized_event_json)
        raw = event.get("raw_event", {})
        return json.dumps({
            "caller": raw.get("caller", event.get("actor", {}).get("identity", "")),
            "operation_name": raw.get("operationName", {}).get("value", event.get("event_name", "")),
            "resource_id": raw.get("resourceId", event.get("target", {}).get("resource_id", "")),
            "resource_group": raw.get("resourceGroupName", ""),
            "subscription_id": raw.get("subscriptionId", ""),
            "correlation_id": raw.get("correlationId", ""),
            "status": raw.get("status", {}).get("value", ""),
            "caller_ip": event.get("network", {}).get("src_ip", raw.get("httpRequest", {}).get("clientIpAddress", "")),
            "tenant_id": raw.get("tenantId", ""),
            "claims": raw.get("claims", {}),
            "severity": event.get("severity", "MEDIUM"),
        })
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def _check_azure_privilege_escalation(normalized_event_json: str) -> str:
    """Check if the Azure event indicates a privilege escalation pattern.

    Returns JSON: {is_escalation: bool, indicators: [str]}
    """
    try:
        event = json.loads(normalized_event_json)
        raw = event.get("raw_event", {})
        op = raw.get("operationName", {}).get("value", "").lower()
        indicators = []
        escalation_ops = [
            "microsoft.authorization/roleassignments/write",
            "microsoft.authorization/roledefinitions/write",
            "microsoft.authorization/policyassignments/write",
            "microsoft.aad/directoryrolemembers/write",
            "microsoft.directory/servicePrincipals/credentials/update",
        ]
        for escalation_op in escalation_ops:
            if escalation_op in op:
                indicators.append(f"privilege_escalation_operation: {op}")
        is_escalation = len(indicators) > 0
        return json.dumps({"is_escalation": is_escalation, "indicators": indicators})
    except Exception as exc:
        return json.dumps({"error": str(exc)})


azure_runbook_agent = LlmAgent(
    name="azure_runbook_agent",
    model=settings.model_name,
    description="Investigates Azure Activity Log security events using Azure-specific runbooks.",
    instruction=(
        "You are the AzureRunbookAgent. You receive a normalized Azure security event as JSON. "
        "1. Call enrich_azure_event to extract caller, operation, resource, and IP context. "
        "2. Call check_azure_privilege_escalation to detect escalation patterns. "
        "3. List available runbooks with list_azure_runbooks. "
        "4. Load the most relevant runbook with load_azure_runbook using the event_name as slug "
        "   (try: unauthorized_access, privilege_escalation, suspicious_signin). "
        "5. Walk through each runbook step analyzing the enriched context. "
        "6. Produce a JSON Finding: "
        "   {finding_id, alert_id, source='azure', severity, title, description, "
        "    remediation_steps, enrichment: {caller, operation, resource, ip, correlation_id}}. "
        "Return only the Finding JSON."
    ),
    tools=[
        FunctionTool(func=_list_azure_runbooks),
        FunctionTool(func=_load_azure_runbook),
        FunctionTool(func=_enrich_azure_event),
        FunctionTool(func=_check_azure_privilege_escalation),
    ],
)

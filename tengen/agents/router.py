"""RouterAgent — routes normalized incidents to the correct runbook agent."""
from __future__ import annotations

import json

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

from ..config import settings
from .azure_runbook import azure_runbook_agent
from .cloudtrail_runbook import cloudtrail_runbook_agent
from .edr_runbook import edr_runbook_agent
from .gcp_audit_runbook import gcp_audit_runbook_agent
from .k8s_runbook import k8s_runbook_agent


def _detect_source_type(event_json: str) -> str:
    """Detect the log source type from a NormalizedEvent or raw Alert JSON.

    Returns: 'aws', 'gcp', 'azure', 'crowdstrike', 'k8s', 'openshift',
             'firewall', 'ddos', or 'unknown'.
    """
    try:
        from ..models.normalized_event import NormalizedEvent
        event = NormalizedEvent.model_validate_json(event_json)
        return event.source_type.value
    except Exception:
        pass
    try:
        data = json.loads(event_json)
        source = data.get("source", data.get("source_type", ""))
        if source:
            return str(source)
        from ..tools.normalizers.registry import detect_source_type
        return detect_source_type(data).value
    except Exception as exc:
        return f"unknown (detection error: {exc})"


def _route_to_queue(source_type: str, incident_json: str) -> str:
    """Use the RouteRegistry to determine which runbook queue this event belongs to.

    Returns the queue name string.
    """
    try:
        from ..routing.registry import registry
        from ..models.normalized_event import NormalizedEvent
        event = NormalizedEvent.model_validate_json(incident_json)
        # Route based on first event in incident or the event itself
        queue = registry.match(event.raw_event)
        return queue or "alerts.dlq"
    except Exception:
        pass
    # Fall back to source_type mapping
    mapping = {
        "aws": "runbook.cloudtrail",
        "gcp": "runbook.gcp.event_audit",
        "azure": "runbook.azure.activity",
        "crowdstrike": "runbook.crowdstrike",
        "k8s": "runbook.k8s",
        "openshift": "runbook.k8s",
        "firewall": "runbook.firewall",
        "ddos": "runbook.firewall",
    }
    return mapping.get(source_type, "alerts.dlq")


router_agent = LlmAgent(
    name="router_agent",
    model=settings.model_name,
    description=(
        "Routes normalized security events to the correct cloud-provider or EDR runbook agent. "
        "Handles AWS, GCP, Azure, CrowdStrike EDR, and Kubernetes."
    ),
    instruction=(
        "You are the RouterAgent. You receive a security event or incident as JSON. "
        "1. Call detect_source_type to determine the log source. "
        "2. Based on the source type, transfer to the correct runbook agent: "
        "   - 'aws': transfer to cloudtrail_runbook_agent "
        "   - 'gcp': transfer to gcp_audit_runbook_agent "
        "   - 'azure': transfer to azure_runbook_agent "
        "   - 'crowdstrike': transfer to edr_runbook_agent "
        "   - 'k8s' or 'openshift': transfer to k8s_runbook_agent "
        "   - 'firewall', 'ddos', or 'unknown': return JSON error: "
        '     {"error": "no runbook agent for source_type", "source_type": "<value>"}. '
        "Pass the original event JSON unchanged to the selected agent. "
        "Return whatever the runbook agent produces."
    ),
    tools=[
        FunctionTool(func=_detect_source_type),
        FunctionTool(func=_route_to_queue),
    ],
    sub_agents=[
        cloudtrail_runbook_agent,
        gcp_audit_runbook_agent,
        azure_runbook_agent,
        edr_runbook_agent,
        k8s_runbook_agent,
    ],
)

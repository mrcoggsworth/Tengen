import json

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

from ..config import settings
from ..tools.enrichment import enrich_gcp_audit_alert
from ..tools.runbook_loader import list_runbooks, load_runbook


def _list_gcp_runbooks() -> str:
    """List all available GCP Audit Log runbooks."""
    runbooks = list_runbooks("gcp")
    return ", ".join(runbooks) if runbooks else "no runbooks found"


def _load_gcp_runbook(event_type: str) -> str:
    """Load a specific GCP Audit Log runbook by event type slug."""
    runbook = load_runbook("gcp", event_type)
    if runbook is None:
        return f"no runbook found for event_type={event_type}"
    return runbook.model_dump_json()


def _enrich_gcp_audit_event(alert_json: str) -> str:
    """Enrich a GCP Audit alert with principal, IP, service, and authorization info."""
    from ..models.alert import Alert

    alert = Alert.model_validate_json(alert_json)
    enrichment = enrich_gcp_audit_alert(alert)
    return json.dumps(enrichment)


gcp_audit_runbook_agent = LlmAgent(
    name="gcp_audit_runbook_agent",
    model=settings.model_name,
    description="Executes GCP Audit Log runbooks for detected security events.",
    instruction=(
        "You are the GCPAuditRunbookAgent. You receive a GCP security alert as JSON and: "
        "1. Enrich the alert using enrich_gcp_audit_event to extract principal and resource context. "
        "2. List available runbooks with list_gcp_runbooks, then load the best match "
        "   with load_gcp_runbook using the alert's event_type. "
        "3. Walk through each runbook step and describe what action would be taken. "
        "4. Produce a JSON Finding with fields: finding_id, alert_id, source='gcp', "
        "   severity, title, description, remediation_steps, enrichment. "
        "Return only the Finding JSON."
    ),
    tools=[
        FunctionTool(func=_list_gcp_runbooks),
        FunctionTool(func=_load_gcp_runbook),
        FunctionTool(func=_enrich_gcp_audit_event),
    ],
)

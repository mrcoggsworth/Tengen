import json

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

from ..config import settings
from ..tools.enrichment import enrich_cloudtrail_alert
from ..tools.runbook_loader import list_runbooks, load_runbook


def _list_aws_runbooks() -> str:
    """List all available AWS CloudTrail runbooks."""
    runbooks = list_runbooks("aws")
    return ", ".join(runbooks) if runbooks else "no runbooks found"


def _load_aws_runbook(event_type: str) -> str:
    """Load a specific AWS CloudTrail runbook by event type slug."""
    runbook = load_runbook("aws", event_type)
    if runbook is None:
        return f"no runbook found for event_type={event_type}"
    return runbook.model_dump_json()


def _enrich_cloudtrail_event(alert_json: str) -> str:
    """Enrich a CloudTrail alert with caller identity, source IP, and error context."""
    from ..models.alert import Alert

    alert = Alert.model_validate_json(alert_json)
    enrichment = enrich_cloudtrail_alert(alert)
    return json.dumps(enrichment)


cloudtrail_runbook_agent = LlmAgent(
    name="cloudtrail_runbook_agent",
    model=settings.model_name,
    description="Executes AWS CloudTrail runbooks for detected security events.",
    instruction=(
        "You are the CloudTrailRunbookAgent. You receive an AWS security alert as JSON and: "
        "1. Enrich the alert using enrich_cloudtrail_event to extract caller context. "
        "2. List available runbooks with list_aws_runbooks, then load the best match "
        "   with load_aws_runbook using the alert's event_type. "
        "3. Walk through each runbook step and describe what action would be taken. "
        "4. Produce a JSON Finding with fields: finding_id, alert_id, source='aws', "
        "   severity, title, description, remediation_steps, enrichment. "
        "Return only the Finding JSON."
    ),
    tools=[
        FunctionTool(func=_list_aws_runbooks),
        FunctionTool(func=_load_aws_runbook),
        FunctionTool(func=_enrich_cloudtrail_event),
    ],
)

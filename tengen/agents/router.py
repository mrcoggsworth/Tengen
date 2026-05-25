from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

from ..config import settings
from .cloudtrail_runbook import cloudtrail_runbook_agent
from .gcp_audit_runbook import gcp_audit_runbook_agent


def _detect_cloud_provider(alert_json: str) -> str:
    """Detect the cloud provider from a normalized Alert's source field."""
    from ..models.alert import Alert

    alert = Alert.model_validate_json(alert_json)
    return alert.source.value


router_agent = LlmAgent(
    name="router_agent",
    model=settings.model_name,
    description="Routes incoming security alerts to the correct cloud-provider runbook agent.",
    instruction=(
        "You are the RouterAgent. You receive a normalized security alert as JSON. "
        "1. Call detect_cloud_provider to determine the source. "
        "2. If source is 'aws', transfer to cloudtrail_runbook_agent passing the alert JSON. "
        "3. If source is 'gcp', transfer to gcp_audit_runbook_agent passing the alert JSON. "
        "4. If source is 'unknown', return: "
        '   {"error": "cannot route alert with unknown cloud provider"}. '
        "Pass the original alert JSON unchanged to the selected agent."
    ),
    tools=[FunctionTool(func=_detect_cloud_provider)],
    sub_agents=[cloudtrail_runbook_agent, gcp_audit_runbook_agent],
)

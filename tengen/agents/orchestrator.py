import json
import uuid

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

from ..config import settings
from ..tools.alert_parser import parse_cloudtrail_event, parse_gcp_audit_event
from .forwarder import forwarder_agent
from .router import router_agent


def _parse_alert(raw_event_json: str, provider: str) -> str:
    """Parse a raw cloud event JSON into a normalized Alert. provider must be 'aws' or 'gcp'."""
    raw_event = json.loads(raw_event_json)
    if provider == "aws":
        alert = parse_cloudtrail_event(raw_event)
    elif provider == "gcp":
        alert = parse_gcp_audit_event(raw_event)
    else:
        from ..models.alert import Alert, AlertSeverity, CloudProvider

        alert = Alert(
            alert_id=str(uuid.uuid4()),
            source=CloudProvider.UNKNOWN,
            severity=AlertSeverity.INFO,
            event_type="Unknown",
            raw_event=raw_event,
            timestamp="",
        )
    return alert.model_dump_json()


def _validate_alert(alert_json: str) -> str:
    """Validate that a parsed Alert is processable. Returns 'valid' or an 'invalid: <reason>' string."""
    from ..models.alert import Alert, CloudProvider

    try:
        alert = Alert.model_validate_json(alert_json)
    except Exception as exc:
        return f"invalid: {exc}"
    if alert.source == CloudProvider.UNKNOWN:
        return "invalid: unknown cloud provider"
    if not alert.event_type:
        return "invalid: missing event_type"
    return "valid"


orchestrator_agent = LlmAgent(
    name="orchestrator_agent",
    model=settings.model_name,
    description=(
        "Top-level SOAR orchestrator that ingests raw cloud security events "
        "and coordinates the full parse → route → runbook → forward pipeline."
    ),
    instruction=(
        "You are the OrchestratorAgent for Tengen SOAR. "
        "When given a raw cloud event, follow these steps exactly: "
        "1. Call parse_alert with the raw event JSON and the provider ('aws' or 'gcp'). "
        "2. Call validate_alert with the parsed Alert JSON. "
        "   If the result starts with 'invalid', stop and return the validation error. "
        "3. Transfer to router_agent with the Alert JSON as the message. "
        "4. After router_agent returns a Finding JSON, transfer to forwarder_agent with that Finding. "
        "5. Return a final plain-text summary: alert_id, finding title, severity, forwarding status."
    ),
    tools=[
        FunctionTool(func=_parse_alert),
        FunctionTool(func=_validate_alert),
    ],
    sub_agents=[router_agent, forwarder_agent],
)

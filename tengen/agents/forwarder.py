from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

from ..config import settings
from ..tools.forwarder_tools import forward_to_pagerduty, forward_to_siem


def _forward_finding_to_siem(finding_json: str) -> str:
    """Forward a security finding to the SIEM platform."""
    from ..models.finding import Finding

    finding = Finding.model_validate_json(finding_json)
    success = forward_to_siem(finding)
    return "forwarded_to_siem" if success else "siem_unavailable"


def _forward_finding_to_pagerduty(finding_json: str) -> str:
    """Forward a critical finding to PagerDuty for on-call alerting."""
    from ..models.finding import Finding

    finding = Finding.model_validate_json(finding_json)
    success = forward_to_pagerduty(finding)
    return "forwarded_to_pagerduty" if success else "pagerduty_unavailable"


forwarder_agent = LlmAgent(
    name="forwarder_agent",
    model=settings.model_name,
    description="Routes enriched security findings to downstream systems such as SIEMs and paging platforms.",
    instruction=(
        "You are the ForwarderAgent. You receive a security finding as JSON and dispatch it "
        "to the appropriate downstream systems. Rules: "
        "- CRITICAL or HIGH severity: forward to both SIEM and PagerDuty. "
        "- MEDIUM severity: forward to SIEM only. "
        "- LOW or INFO severity: log the finding but do not forward it. "
        "Return a brief summary of the finding title, severity, and where it was forwarded."
    ),
    tools=[
        FunctionTool(func=_forward_finding_to_siem),
        FunctionTool(func=_forward_finding_to_pagerduty),
    ],
)

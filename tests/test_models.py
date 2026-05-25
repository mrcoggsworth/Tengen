"""Tests 1-3: Pydantic model validation and field contracts."""
from tengen.models.alert import Alert, AlertSeverity, CloudProvider
from tengen.models.finding import Finding, RemediationStep
from tengen.models.runbook import Runbook, RunbookStep


def test_alert_model_validation():
    alert = Alert(
        alert_id="test-001",
        source=CloudProvider.AWS,
        severity=AlertSeverity.HIGH,
        event_type="AssumeRole",
        raw_event={"eventName": "AssumeRole"},
        timestamp="2024-01-15T10:30:00Z",
        account_id="123456789012",
        region="us-east-1",
    )
    assert alert.alert_id == "test-001"
    assert alert.source == CloudProvider.AWS
    assert alert.severity == AlertSeverity.HIGH
    assert alert.region == "us-east-1"


def test_finding_model_severity_levels():
    finding = Finding(
        finding_id="find-001",
        alert_id="test-001",
        source=CloudProvider.AWS,
        severity=AlertSeverity.CRITICAL,
        title="Root Account Usage Detected",
        description="The root account was used to perform API calls.",
        remediation_steps=[
            RemediationStep(order=1, action="Revoke active sessions", automated=False),
            RemediationStep(order=2, action="Enable MFA on root account", automated=False),
        ],
    )
    assert finding.severity == AlertSeverity.CRITICAL
    assert len(finding.remediation_steps) == 2
    assert not finding.forwarded
    assert finding.forwarding_targets == []


def test_runbook_model_step_execution():
    runbook = Runbook(
        name="unauthorized_api_call",
        event_type="UnauthorizedAPICall",
        cloud_provider="aws",
        severity="high",
        description="Runbook for unauthorized AWS API calls",
        steps=[
            RunbookStep(
                order=1,
                name="identify_caller",
                description="Extract caller identity from the event",
                tool="enrich_cloudtrail_event",
            ),
            RunbookStep(
                order=2,
                name="check_ip_reputation",
                description="Query threat intel for source IP",
                tool="ip_reputation_lookup",
                automated=True,
            ),
        ],
    )
    assert len(runbook.steps) == 2
    assert runbook.steps[0].order == 1
    assert runbook.steps[1].automated is True

"""Tests 8-10: RouterAgent provider detection."""
from tengen.agents.router import _detect_cloud_provider
from tengen.models.alert import Alert, AlertSeverity, CloudProvider
from tengen.tools.alert_parser import parse_cloudtrail_event, parse_gcp_audit_event


def test_router_identifies_aws_source(sample_cloudtrail_event):
    alert = parse_cloudtrail_event(sample_cloudtrail_event)
    provider = _detect_cloud_provider(alert.model_dump_json())
    assert provider == "aws"


def test_router_identifies_gcp_source(sample_gcp_audit_event):
    alert = parse_gcp_audit_event(sample_gcp_audit_event)
    provider = _detect_cloud_provider(alert.model_dump_json())
    assert provider == "gcp"


def test_router_unknown_source_returns_unknown():
    alert = Alert(
        alert_id="x",
        source=CloudProvider.UNKNOWN,
        severity=AlertSeverity.INFO,
        event_type="Unknown",
        raw_event={},
        timestamp="",
    )
    provider = _detect_cloud_provider(alert.model_dump_json())
    assert provider == "unknown"

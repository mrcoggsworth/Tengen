"""Tests 5-7: OrchestratorAgent tool functions."""
import json

from tengen.agents.orchestrator import _parse_alert, _validate_alert
from tengen.models.alert import Alert, CloudProvider


def test_parse_alert_cloudtrail(sample_cloudtrail_event):
    raw_json = json.dumps(sample_cloudtrail_event)
    result = _parse_alert(raw_json, "aws")
    alert = Alert.model_validate_json(result)
    assert alert.source == CloudProvider.AWS
    assert alert.event_type == "AssumeRole"
    assert alert.account_id == "123456789012"


def test_parse_alert_unknown_provider(sample_cloudtrail_event):
    raw_json = json.dumps(sample_cloudtrail_event)
    result = _parse_alert(raw_json, "azure")
    alert = Alert.model_validate_json(result)
    assert alert.source == CloudProvider.UNKNOWN
    assert alert.event_type == "Unknown"


def test_validate_alert_rejects_unknown_provider(sample_cloudtrail_event):
    raw_json = json.dumps(sample_cloudtrail_event)
    alert_json = _parse_alert(raw_json, "azure")
    result = _validate_alert(alert_json)
    assert result.startswith("invalid")
    assert "unknown cloud provider" in result

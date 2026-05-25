"""Test 4: Alert parser correctly maps CloudTrail event fields."""
from tengen.models.alert import AlertSeverity, CloudProvider
from tengen.tools.alert_parser import parse_cloudtrail_event


def test_alert_parser_cloudtrail_access_denied(sample_cloudtrail_event):
    alert = parse_cloudtrail_event(sample_cloudtrail_event)
    assert alert.source == CloudProvider.AWS
    assert alert.severity == AlertSeverity.HIGH
    assert alert.event_type == "AssumeRole"
    assert alert.region == "us-east-1"
    assert alert.account_id == "123456789012"
    assert alert.alert_id  # UUID was generated

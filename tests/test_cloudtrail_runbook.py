"""Tests 11-13: CloudTrailRunbookAgent tool functions."""
import json

from tengen.agents.cloudtrail_runbook import (
    _enrich_cloudtrail_event,
    _list_aws_runbooks,
    _load_aws_runbook,
)
from tengen.tools.alert_parser import parse_cloudtrail_event


def test_enrich_cloudtrail_event_extracts_fields(sample_cloudtrail_event):
    alert = parse_cloudtrail_event(sample_cloudtrail_event)
    enrichment_json = _enrich_cloudtrail_event(alert.model_dump_json())
    enrichment = json.loads(enrichment_json)
    assert enrichment["source_ip"] == "203.0.113.10"
    assert enrichment["error_code"] == "AccessDenied"
    assert enrichment["user_identity_type"] == "IAMUser"
    assert enrichment["user_arn"] == "arn:aws:iam::123456789012:user/alice"


def test_load_aws_runbook_returns_not_found_for_missing():
    result = _load_aws_runbook("nonexistent_event_xyz")
    assert "no runbook found" in result
    assert "nonexistent_event_xyz" in result


def test_list_aws_runbooks_returns_string():
    result = _list_aws_runbooks()
    assert isinstance(result, str)
    assert len(result) > 0

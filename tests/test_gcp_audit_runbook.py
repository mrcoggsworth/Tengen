"""Tests 14-15: GCPAuditRunbookAgent tool functions."""
import json

from tengen.agents.gcp_audit_runbook import _enrich_gcp_audit_event, _load_gcp_runbook
from tengen.tools.alert_parser import parse_gcp_audit_event


def test_enrich_gcp_audit_event_extracts_fields(sample_gcp_audit_event):
    alert = parse_gcp_audit_event(sample_gcp_audit_event)
    enrichment_json = _enrich_gcp_audit_event(alert.model_dump_json())
    enrichment = json.loads(enrichment_json)
    assert enrichment["principal_email"] == "user@example.com"
    assert enrichment["caller_ip"] == "198.51.100.5"
    assert enrichment["service_name"] == "storage.googleapis.com"
    assert enrichment["resource_name"] == "projects/_/buckets/sensitive-data"


def test_load_gcp_runbook_returns_not_found_for_missing():
    result = _load_gcp_runbook("nonexistent_gcp_event_xyz")
    assert "no runbook found" in result
    assert "nonexistent_gcp_event_xyz" in result

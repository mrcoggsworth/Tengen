"""Tests for n8n response parser."""
from tengen.models.alert import Alert
from tengen.n8n.response_parser import parse_response


def _make_alert(**kwargs) -> Alert:
    defaults = {"source": "kafka", "raw_payload": {"eventName": "ConsoleLogin"}}
    defaults.update(kwargs)
    return Alert(**defaults)


def test_parse_freeform_response():
    alert = _make_alert()
    n8n_response = {
        "ip_reputation": "malicious",
        "geo": {"country": "RU", "city": "Moscow"},
        "verdict": "suspicious",
        "severity": "high",
        "recommendations": ["Block IP", "Reset credentials"],
        "iocs": [{"type": "ip", "value": "1.2.3.4"}],
    }
    result = parse_response(n8n_response, alert, route_path="aws.cloudtrail.root_login")

    assert result.enrichment == n8n_response
    assert result.enrichment_error is False
    assert result.n8n_route_path == "aws.cloudtrail.root_login"
    assert result.alert.id == alert.id
    assert result.runbook == "n8n.aws.cloudtrail.root_login"


def test_parse_minimal_response():
    alert = _make_alert()
    n8n_response = {"status": "processed"}
    result = parse_response(n8n_response, alert, route_path="_default")

    assert result.enrichment == {"status": "processed"}
    assert result.n8n_route_path == "_default"
    assert result.runbook == "n8n._default"


def test_parse_empty_response_sets_enrichment_error():
    alert = _make_alert()
    result = parse_response({}, alert, route_path="aws._default")

    assert result.enrichment == {}
    assert result.enrichment_error is True
    assert result.n8n_route_path == "aws._default"


def test_parse_none_response_sets_enrichment_error():
    alert = _make_alert()
    result = parse_response(None, alert, route_path="aws._default")

    assert result.enrichment == {}
    assert result.enrichment_error is True


def test_parse_preserves_original_alert_id():
    alert = _make_alert()
    original_id = alert.id
    n8n_response = {"result": "ok"}
    result = parse_response(n8n_response, alert, route_path="test")
    assert result.alert.id == original_id


def test_parse_extracts_well_known_fields_into_extracted():
    alert = _make_alert()
    n8n_response = {
        "severity": "critical",
        "recommendations": ["Isolate host"],
        "iocs": [{"type": "hash", "value": "abc123"}],
        "verdict": "malicious",
        "custom_field": "preserved",
    }
    result = parse_response(n8n_response, alert, route_path="test")

    assert result.extracted["severity"] == "critical"
    assert result.extracted["recommendations"] == ["Isolate host"]
    assert result.extracted["iocs"] == [{"type": "hash", "value": "abc123"}]
    assert result.extracted["verdict"] == "malicious"
    # Full response still in enrichment
    assert result.enrichment == n8n_response

"""Tests for updated EnrichedAlert model with n8n fields."""
from tengen.models.alert import Alert
from tengen.models.enriched_alert import EnrichedAlert


def _make_alert(**kwargs) -> Alert:
    defaults = {"source": "test", "raw_payload": {"key": "value"}}
    defaults.update(kwargs)
    return Alert(**defaults)


def test_enriched_alert_with_n8n_enrichment():
    alert = _make_alert()
    ea = EnrichedAlert(
        alert=alert,
        runbook="n8n.aws.cloudtrail.root_login",
        enrichment={"ip_reputation": "malicious", "geo": "RU"},
    )
    assert ea.enrichment == {"ip_reputation": "malicious", "geo": "RU"}
    assert ea.enrichment_error is False
    assert ea.n8n_route_path == ""


def test_enriched_alert_with_enrichment_error():
    alert = _make_alert()
    ea = EnrichedAlert(
        alert=alert,
        runbook="n8n.general",
        enrichment_error=True,
        n8n_route_path="aws.cloudtrail._default",
    )
    assert ea.enrichment_error is True
    assert ea.n8n_route_path == "aws.cloudtrail._default"


def test_enriched_alert_backwards_compatible():
    """Existing fields still work — extracted, runbook_error, destination."""
    alert = _make_alert()
    ea = EnrichedAlert(
        alert=alert,
        runbook="cloud.aws.cloudtrail",
        extracted={"actor": "root"},
        runbook_error="timeout",
        destination="pagerduty",
    )
    assert ea.extracted == {"actor": "root"}
    assert ea.runbook_error == "timeout"
    assert ea.destination == "pagerduty"


def test_enriched_alert_default_enrichment_is_empty():
    alert = _make_alert()
    ea = EnrichedAlert(alert=alert, runbook="test")
    assert ea.enrichment == {}
    assert ea.enrichment_error is False
    assert ea.n8n_route_path == ""

"""Tests 16-17: ForwarderAgent tool functions — no-op when targets are unconfigured."""
from unittest.mock import patch

import pytest

from tengen.agents.forwarder import _forward_finding_to_pagerduty, _forward_finding_to_siem
from tengen.models.alert import AlertSeverity, CloudProvider
from tengen.models.finding import Finding


@pytest.fixture
def sample_finding():
    return Finding(
        finding_id="find-001",
        alert_id="alert-001",
        source=CloudProvider.AWS,
        severity=AlertSeverity.HIGH,
        title="Unauthorized API Call",
        description="An unauthorized API call was detected from an external IP.",
    )


def test_forwarder_siem_skipped_when_no_endpoint(sample_finding):
    with patch("tengen.tools.forwarder_tools.settings") as mock_settings:
        mock_settings.siem_endpoint = ""
        result = _forward_finding_to_siem(sample_finding.model_dump_json())
    assert result == "siem_unavailable"


def test_forwarder_pagerduty_skipped_when_no_key(sample_finding):
    with patch("tengen.tools.forwarder_tools.settings") as mock_settings:
        mock_settings.pagerduty_api_key = ""
        result = _forward_finding_to_pagerduty(sample_finding.model_dump_json())
    assert result == "pagerduty_unavailable"

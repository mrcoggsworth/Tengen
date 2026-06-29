"""Tests for the rewritten router agent n8n tool wrappers."""
import json
import os
from unittest.mock import patch

import pytest

from tengen.n8n.route_resolver import RouteMatch

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
ROUTES_YAML = os.path.join(FIXTURES_DIR, "n8n_routes.yaml")


@pytest.fixture(autouse=True)
def _set_routes_path(monkeypatch):
    monkeypatch.setenv("N8N_ROUTES_PATH", ROUTES_YAML)


def test_resolve_route_returns_match():
    # Must import after env is set
    from tengen.agents.router import _resolve_route
    result = json.loads(_resolve_route("aws", "cloudtrail", "root_login"))
    assert result["webhook_url"] == "https://n8n.example.com/webhook/aws-ct-root"
    assert result["route_path"] == "aws.cloudtrail.root_login"


def test_resolve_route_falls_back_to_default():
    from tengen.agents.router import _resolve_route
    result = json.loads(_resolve_route("unknown_vendor", "unknown_cat", None))
    assert result["webhook_url"] == "https://n8n.example.com/webhook/general-triage"


def test_execute_webhook_success():
    from tengen.agents.router import _execute_webhook
    mock_response = {"result": "enriched", "severity": "high"}
    with patch("tengen.agents.router._n8n_client.execute_sync", return_value=mock_response):
        result = json.loads(_execute_webhook(
            "https://n8n.example.com/webhook/test",
            json.dumps({"event": "data"}),
        ))
    assert result == {"result": "enriched", "severity": "high"}


def test_execute_webhook_failure():
    from tengen.agents.router import _execute_webhook
    from tengen.n8n.client import N8nRequestFailed
    error = N8nRequestFailed(
        url="https://n8n.example.com/webhook/test",
        status=500,
        detail="Internal Server Error",
        attempts=3,
    )
    with patch("tengen.agents.router._n8n_client.execute_sync", side_effect=error):
        result = json.loads(_execute_webhook(
            "https://n8n.example.com/webhook/test",
            json.dumps({"event": "data"}),
        ))
    assert result["error"] == "webhook_failed"
    assert result["dlq"] is True
    assert "500" in result["details"]


def test_router_agent_has_correct_tools():
    from tengen.agents.router import router_agent
    tool_names = [t.name for t in router_agent.tools]
    assert "resolve_route" in tool_names
    assert "execute_webhook" in tool_names


def test_router_agent_has_no_sub_agents():
    from tengen.agents.router import router_agent
    assert not router_agent.sub_agents

"""Tests for n8n route resolver."""
import os
import tempfile
import time

import pytest
import yaml

from tengen.n8n.route_resolver import NoRouteError, RouteMatch, RouteResolver

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
ROUTES_YAML = os.path.join(FIXTURES_DIR, "n8n_routes.yaml")


@pytest.fixture
def resolver():
    return RouteResolver(ROUTES_YAML)


def test_exact_match_three_levels(resolver):
    match = resolver.resolve("aws", "cloudtrail", "root_login")
    assert match.webhook_url == "https://n8n.example.com/webhook/aws-ct-root"
    assert match.route_path == "aws.cloudtrail.root_login"
    assert match.description == "Root account console or API activity"


def test_category_default_when_event_type_unknown(resolver):
    match = resolver.resolve("aws", "cloudtrail", "some_unknown_event")
    assert match.webhook_url == "https://n8n.example.com/webhook/aws-ct-general"
    assert match.route_path == "aws.cloudtrail._default"


def test_vendor_default_when_category_unknown(resolver):
    match = resolver.resolve("aws", "guardduty", None)
    assert match.webhook_url == "https://n8n.example.com/webhook/aws-general"
    assert match.route_path == "aws._default"


def test_root_default_when_vendor_unknown(resolver):
    match = resolver.resolve("unknown_vendor", "whatever", None)
    assert match.webhook_url == "https://n8n.example.com/webhook/general-triage"
    assert match.route_path == "_default"


def test_two_level_match(resolver):
    match = resolver.resolve("crowdstrike", "windows", "powershell_execution")
    assert match.webhook_url == "https://n8n.example.com/webhook/cs-win-powershell"
    assert match.route_path == "crowdstrike.windows.powershell_execution"


def test_none_event_type_falls_to_category_default(resolver):
    match = resolver.resolve("crowdstrike", "windows", None)
    assert match.webhook_url == "https://n8n.example.com/webhook/cs-windows"
    assert match.route_path == "crowdstrike.windows._default"


def test_no_route_error_when_no_defaults():
    """A YAML with no _default at root raises NoRouteError."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump({"version": "1", "routes": {"aws": {"cloudtrail": {"webhook": "http://x"}}}}, f)
        f.flush()
        resolver = RouteResolver(f.name)
    with pytest.raises(NoRouteError):
        resolver.resolve("gcp", "audit", None)
    os.unlink(f.name)


def test_reload_on_file_change():
    """Resolver reloads when the file mtime changes."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump({
            "version": "1",
            "routes": {"_default": {"webhook": "http://old"}}
        }, f)
        path = f.name

    resolver = RouteResolver(path)
    assert resolver.resolve("x", "y", None).webhook_url == "http://old"

    time.sleep(0.05)
    with open(path, "w") as f:
        yaml.dump({
            "version": "1",
            "routes": {"_default": {"webhook": "http://new"}}
        }, f)

    assert resolver.resolve("x", "y", None).webhook_url == "http://new"
    os.unlink(path)


def test_route_match_is_dataclass():
    rm = RouteMatch(webhook_url="http://x", route_path="a.b", description="desc")
    assert rm.webhook_url == "http://x"
    assert rm.route_path == "a.b"
    assert rm.description == "desc"

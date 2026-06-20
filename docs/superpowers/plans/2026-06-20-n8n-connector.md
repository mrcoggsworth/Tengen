# n8n Connector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace in-process runbook agents and enrichment pipeline with a webhook-based n8n connector, keeping ingestion/normalization/triage/routing in Tengen.

**Architecture:** Router agent uses two ADK tools (`resolve_route`, `execute_webhook`) to dispatch events to n8n workflows via HTTP POST. A hierarchical YAML routing spec (mounted as OpenShift ConfigMap) maps vendor/category/event_type to n8n webhook URLs. Responses are freeform JSON parsed into `EnrichedAlert` for forwarding.

**Tech Stack:** Python 3.11+, google-adk, pydantic, httpx, pyyaml, pytest

**Spec:** `docs/superpowers/specs/2026-06-20-n8n-connector-design.md`

---

### Task 1: Add n8n settings to config

**Files:**
- Modify: `tengen/config.py`

- [ ] **Step 1: Add n8n settings to the Settings dataclass**

Add these fields after the `siem_endpoint` line (line 80) in `tengen/config.py`:

```python
    # ── n8n ───────────────────────────────────────────────────────────────────
    n8n_routes_path: str = field(default_factory=lambda: os.getenv("N8N_ROUTES_PATH", "/etc/tengen/n8n_routes.yaml"))
    n8n_timeout: int = field(default_factory=lambda: int(os.getenv("N8N_TIMEOUT", "30")))
    n8n_max_retries: int = field(default_factory=lambda: int(os.getenv("N8N_MAX_RETRIES", "3")))
    n8n_backoff_base: int = field(default_factory=lambda: int(os.getenv("N8N_BACKOFF_BASE", "2")))
```

- [ ] **Step 2: Verify config loads**

Run: `python -c "from tengen.config import settings; print(settings.n8n_routes_path, settings.n8n_timeout, settings.n8n_max_retries, settings.n8n_backoff_base)"`

Expected: `/etc/tengen/n8n_routes.yaml 30 3 2`

- [ ] **Step 3: Commit**

```bash
git add tengen/config.py
git commit -m "feat(n8n): add n8n settings to config"
```

---

### Task 2: Route resolver

**Files:**
- Create: `tengen/n8n/__init__.py`
- Create: `tengen/n8n/route_resolver.py`
- Create: `tests/test_route_resolver.py`
- Create: `tests/fixtures/n8n_routes.yaml`

- [ ] **Step 1: Create test fixtures YAML**

Create `tests/fixtures/n8n_routes.yaml`:

```yaml
version: "1"

routes:
  aws:
    description: "Amazon Web Services security events"
    cloudtrail:
      description: "CloudTrail API audit logs"
      root_login:
        webhook: https://n8n.example.com/webhook/aws-ct-root
        description: "Root account console or API activity"
      unauthorized_api:
        webhook: https://n8n.example.com/webhook/aws-ct-unauth
        description: "AccessDenied or UnauthorizedAccess events"
      _default:
        webhook: https://n8n.example.com/webhook/aws-ct-general
    _default:
      webhook: https://n8n.example.com/webhook/aws-general

  crowdstrike:
    description: "CrowdStrike EDR detections"
    windows:
      powershell_execution:
        webhook: https://n8n.example.com/webhook/cs-win-powershell
        description: "Suspicious or unknown PowerShell execution"
      _default:
        webhook: https://n8n.example.com/webhook/cs-windows
    _default:
      webhook: https://n8n.example.com/webhook/cs-general

  _default:
    webhook: https://n8n.example.com/webhook/general-triage
    description: "Catch-all for unrecognized vendors or event types"
```

- [ ] **Step 2: Write the failing tests**

Create `tests/test_route_resolver.py`:

```python
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `python -m pytest tests/test_route_resolver.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'tengen.n8n'`

- [ ] **Step 4: Create the n8n package init**

Create `tengen/n8n/__init__.py`:

```python
"""n8n webhook connector package."""
```

- [ ] **Step 5: Implement route_resolver.py**

Create `tengen/n8n/route_resolver.py`:

```python
"""Hierarchical YAML route resolver for n8n webhook dispatch."""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_RESERVED_KEYS = {"webhook", "description", "version", "_default"}


class NoRouteError(Exception):
    """No matching route found and no _default fallback exists."""


@dataclass(frozen=True, slots=True)
class RouteMatch:
    """Resolved route to an n8n webhook."""

    webhook_url: str
    route_path: str
    description: str


class RouteResolver:
    """Loads a hierarchical YAML routing spec and resolves vendor/category/event_type to a webhook URL.

    Checks file mtime on each resolve() call and reloads if changed.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._mtime: float = 0.0
        self._routes: dict[str, Any] = {}
        self._load()

    def resolve(self, vendor: str, category: str, event_type: str | None) -> RouteMatch:
        """Walk the route tree from most-specific to least-specific.

        Resolution order:
          1. routes[vendor][category][event_type]  (if event_type given)
          2. routes[vendor][category][_default]
          3. routes[vendor][_default]
          4. routes[_default]

        Raises NoRouteError if nothing matches.
        """
        self._reload_if_changed()

        routes = self._routes

        # Level 1: vendor
        vendor_node = routes.get(vendor)
        if vendor_node and isinstance(vendor_node, dict) and "webhook" not in vendor_node:
            # Level 2: category
            cat_node = vendor_node.get(category)
            if cat_node and isinstance(cat_node, dict) and "webhook" not in cat_node:
                # Level 3: event_type
                if event_type:
                    evt_node = cat_node.get(event_type)
                    if evt_node and isinstance(evt_node, dict) and "webhook" in evt_node:
                        return RouteMatch(
                            webhook_url=evt_node["webhook"],
                            route_path=f"{vendor}.{category}.{event_type}",
                            description=evt_node.get("description", ""),
                        )
                # Category _default
                cat_default = cat_node.get("_default")
                if cat_default and isinstance(cat_default, dict) and "webhook" in cat_default:
                    return RouteMatch(
                        webhook_url=cat_default["webhook"],
                        route_path=f"{vendor}.{category}._default",
                        description=cat_default.get("description", ""),
                    )
            elif cat_node and isinstance(cat_node, dict) and "webhook" in cat_node:
                # Category is a leaf node with webhook
                return RouteMatch(
                    webhook_url=cat_node["webhook"],
                    route_path=f"{vendor}.{category}",
                    description=cat_node.get("description", ""),
                )
            # Vendor _default
            vendor_default = vendor_node.get("_default")
            if vendor_default and isinstance(vendor_default, dict) and "webhook" in vendor_default:
                return RouteMatch(
                    webhook_url=vendor_default["webhook"],
                    route_path=f"{vendor}._default",
                    description=vendor_default.get("description", ""),
                )
        elif vendor_node and isinstance(vendor_node, dict) and "webhook" in vendor_node:
            # Vendor is a leaf node with webhook
            return RouteMatch(
                webhook_url=vendor_node["webhook"],
                route_path=vendor,
                description=vendor_node.get("description", ""),
            )

        # Root _default
        root_default = routes.get("_default")
        if root_default and isinstance(root_default, dict) and "webhook" in root_default:
            return RouteMatch(
                webhook_url=root_default["webhook"],
                route_path="_default",
                description=root_default.get("description", ""),
            )

        raise NoRouteError(f"No route for vendor={vendor}, category={category}, event_type={event_type}")

    def _load(self) -> None:
        with open(self._path) as f:
            data = yaml.safe_load(f)
        self._routes = data.get("routes", {})
        self._mtime = os.path.getmtime(self._path)
        logger.info("Loaded n8n routes from %s (%d top-level entries)", self._path, len(self._routes))

    def _reload_if_changed(self) -> None:
        try:
            current_mtime = os.path.getmtime(self._path)
        except OSError:
            return
        if current_mtime != self._mtime:
            logger.info("Route file changed, reloading: %s", self._path)
            self._load()
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `python -m pytest tests/test_route_resolver.py -v`
Expected: all 9 tests PASS

- [ ] **Step 7: Commit**

```bash
git add tengen/n8n/ tests/test_route_resolver.py tests/fixtures/n8n_routes.yaml
git commit -m "feat(n8n): route resolver with hierarchical YAML lookup"
```

---

### Task 3: n8n HTTP client

**Files:**
- Create: `tengen/n8n/client.py`
- Create: `tests/test_n8n_client.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_n8n_client.py`:

```python
"""Tests for n8n HTTP client with retry and backoff."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from tengen.n8n.client import N8nClient, N8nRequestFailed


@pytest.fixture
def client():
    return N8nClient(timeout=5, max_retries=3, backoff_base=0.01)


@pytest.mark.asyncio
async def test_successful_post(client):
    mock_response = httpx.Response(200, json={"result": "ok"})
    with patch.object(client._client, "post", new_callable=AsyncMock, return_value=mock_response):
        result = await client.execute("https://n8n.example.com/webhook/test", {"event": "data"})
    assert result == {"result": "ok"}


@pytest.mark.asyncio
async def test_retries_on_500(client):
    fail = httpx.Response(500, text="Internal Server Error")
    success = httpx.Response(200, json={"result": "ok"})
    mock_post = AsyncMock(side_effect=[fail, fail, success])
    with patch.object(client._client, "post", mock_post):
        result = await client.execute("https://n8n.example.com/webhook/test", {"event": "data"})
    assert result == {"result": "ok"}
    assert mock_post.call_count == 3


@pytest.mark.asyncio
async def test_raises_after_exhausted_retries(client):
    fail = httpx.Response(500, text="Internal Server Error")
    mock_post = AsyncMock(return_value=fail)
    with patch.object(client._client, "post", mock_post):
        with pytest.raises(N8nRequestFailed) as exc_info:
            await client.execute("https://n8n.example.com/webhook/test", {"event": "data"})
    assert "500" in str(exc_info.value)
    assert mock_post.call_count == 3


@pytest.mark.asyncio
async def test_no_retry_on_4xx(client):
    fail = httpx.Response(422, json={"error": "bad payload"})
    mock_post = AsyncMock(return_value=fail)
    with patch.object(client._client, "post", mock_post):
        with pytest.raises(N8nRequestFailed) as exc_info:
            await client.execute("https://n8n.example.com/webhook/test", {"bad": True})
    assert "422" in str(exc_info.value)
    assert mock_post.call_count == 1  # No retry


@pytest.mark.asyncio
async def test_retries_on_timeout(client):
    success = httpx.Response(200, json={"ok": True})
    mock_post = AsyncMock(side_effect=[httpx.TimeoutException("timed out"), success])
    with patch.object(client._client, "post", mock_post):
        result = await client.execute("https://n8n.example.com/webhook/test", {"event": "data"})
    assert result == {"ok": True}
    assert mock_post.call_count == 2


@pytest.mark.asyncio
async def test_retries_on_connect_error(client):
    success = httpx.Response(200, json={"ok": True})
    mock_post = AsyncMock(side_effect=[httpx.ConnectError("refused"), success])
    with patch.object(client._client, "post", mock_post):
        result = await client.execute("https://n8n.example.com/webhook/test", {"event": "data"})
    assert result == {"ok": True}


@pytest.mark.asyncio
async def test_execute_sync(client):
    mock_response = httpx.Response(200, json={"sync": True})
    with patch.object(client._client, "post", new_callable=AsyncMock, return_value=mock_response):
        result = client.execute_sync("https://n8n.example.com/webhook/test", {"event": "data"})
    assert result == {"sync": True}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_n8n_client.py -v`
Expected: FAIL — `ImportError: cannot import name 'N8nClient'`

- [ ] **Step 3: Implement client.py**

Create `tengen/n8n/client.py`:

```python
"""n8n webhook HTTP client with retry and exponential backoff."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class N8nRequestFailed(Exception):
    """All retries exhausted or non-retryable HTTP error."""

    def __init__(self, url: str, status: int | None, detail: str, attempts: int) -> None:
        self.url = url
        self.status = status
        self.detail = detail
        self.attempts = attempts
        super().__init__(f"n8n request failed: url={url} status={status} attempts={attempts} detail={detail}")


class N8nClient:
    """POST payloads to n8n webhooks with retry logic.

    Retries on 5xx, timeout, and connection errors.
    No retry on 4xx (client error — not transient).
    """

    def __init__(
        self,
        timeout: int = 30,
        max_retries: int = 3,
        backoff_base: float = 2.0,
    ) -> None:
        self._timeout = timeout
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._client = httpx.AsyncClient(timeout=timeout)

    async def execute(self, webhook_url: str, payload: dict[str, Any]) -> dict[str, Any]:
        """POST payload to webhook_url and return parsed JSON response.

        Retries up to max_retries on transient failures.
        Raises N8nRequestFailed on exhausted retries or non-retryable errors.
        """
        last_error: str = ""
        last_status: int | None = None

        for attempt in range(self._max_retries):
            try:
                response = await self._client.post(webhook_url, json=payload)

                if response.status_code < 400:
                    return response.json()

                # 4xx — client error, don't retry
                if 400 <= response.status_code < 500:
                    raise N8nRequestFailed(
                        url=webhook_url,
                        status=response.status_code,
                        detail=response.text[:500],
                        attempts=1,
                    )

                # 5xx — server error, retry
                last_status = response.status_code
                last_error = response.text[:500]
                logger.warning(
                    "n8n webhook %s returned %d (attempt %d/%d)",
                    webhook_url, response.status_code, attempt + 1, self._max_retries,
                )

            except (httpx.TimeoutException, httpx.ConnectError) as exc:
                last_status = None
                last_error = str(exc)
                logger.warning(
                    "n8n webhook %s connection error (attempt %d/%d): %s",
                    webhook_url, attempt + 1, self._max_retries, exc,
                )

            except N8nRequestFailed:
                raise

            # Backoff before next attempt (skip after last attempt)
            if attempt < self._max_retries - 1:
                delay = self._backoff_base ** attempt
                await asyncio.sleep(delay)

        raise N8nRequestFailed(
            url=webhook_url,
            status=last_status,
            detail=last_error,
            attempts=self._max_retries,
        )

    def execute_sync(self, webhook_url: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Sync wrapper for use in ADK FunctionTool contexts."""
        return asyncio.run(self.execute(webhook_url, payload))

    async def close(self) -> None:
        await self._client.aclose()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_n8n_client.py -v`
Expected: all 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add tengen/n8n/client.py tests/test_n8n_client.py
git commit -m "feat(n8n): HTTP client with retry and exponential backoff"
```

---

### Task 4: Update EnrichedAlert model

**Files:**
- Modify: `tengen/models/enriched_alert.py`
- Create: `tests/test_enriched_alert.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_enriched_alert.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_enriched_alert.py -v`
Expected: FAIL — `EnrichedAlert` does not have `enrichment` field yet

- [ ] **Step 3: Update the EnrichedAlert model**

Replace `tengen/models/enriched_alert.py` with:

```python
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

from .alert import Alert


class EnrichedAlert(BaseModel):
    """Alert after runbook/n8n processing.

    Published to the enriched queue for forwarding.
    The original Alert is embedded unchanged so all source fields are preserved.
    """

    alert: Alert
    runbook: str  # dot-separated: "n8n.aws.cloudtrail" or legacy "cloud.aws.cloudtrail"
    enriched_at: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    extracted: dict[str, Any] = Field(default_factory=dict)
    runbook_error: str | None = None
    destination: Literal["splunk", "universal", "pagerduty"] = "splunk"

    # n8n-specific fields
    enrichment: dict[str, Any] = Field(default_factory=dict)
    enrichment_error: bool = False
    n8n_route_path: str = ""

    model_config = {"frozen": True}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_enriched_alert.py -v`
Expected: all 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add tengen/models/enriched_alert.py tests/test_enriched_alert.py
git commit -m "feat(models): add n8n enrichment fields to EnrichedAlert"
```

---

### Task 5: Response parser

**Files:**
- Create: `tengen/n8n/response_parser.py`
- Create: `tests/test_response_parser.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_response_parser.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_response_parser.py -v`
Expected: FAIL — `ImportError: cannot import name 'parse_response'`

- [ ] **Step 3: Implement response_parser.py**

Create `tengen/n8n/response_parser.py`:

```python
"""Parse freeform n8n webhook responses into EnrichedAlert."""
from __future__ import annotations

import logging
from typing import Any

from tengen.models.alert import Alert
from tengen.models.enriched_alert import EnrichedAlert

logger = logging.getLogger(__name__)

_WELL_KNOWN_FIELDS = ("severity", "recommendations", "iocs", "verdict")


def parse_response(
    raw_response: dict[str, Any] | None,
    original_alert: Alert,
    route_path: str,
) -> EnrichedAlert:
    """Map a freeform n8n JSON response into an EnrichedAlert.

    - Preserves the original alert unchanged.
    - Stuffs the entire n8n response into ``enrichment``.
    - Extracts well-known fields (severity, recommendations, iocs, verdict)
      into ``extracted`` if present.
    - Sets ``enrichment_error=True`` on empty or None responses.
    """
    if not raw_response:
        logger.warning("Empty n8n response for route %s, alert %s", route_path, original_alert.id)
        return EnrichedAlert(
            alert=original_alert,
            runbook=f"n8n.{route_path}",
            enrichment={},
            enrichment_error=True,
            n8n_route_path=route_path,
        )

    extracted: dict[str, Any] = {}
    for key in _WELL_KNOWN_FIELDS:
        if key in raw_response:
            extracted[key] = raw_response[key]

    return EnrichedAlert(
        alert=original_alert,
        runbook=f"n8n.{route_path}",
        enrichment=raw_response,
        extracted=extracted,
        enrichment_error=False,
        n8n_route_path=route_path,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_response_parser.py -v`
Expected: all 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add tengen/n8n/response_parser.py tests/test_response_parser.py
git commit -m "feat(n8n): response parser maps freeform JSON to EnrichedAlert"
```

---

### Task 6: n8n package public API

**Files:**
- Modify: `tengen/n8n/__init__.py`

- [ ] **Step 1: Update the package init with public exports**

Replace `tengen/n8n/__init__.py` with:

```python
"""n8n webhook connector package.

Public API:
    RouteResolver, RouteMatch, NoRouteError — route resolution
    N8nClient, N8nRequestFailed — HTTP dispatch
    parse_response — response mapping to EnrichedAlert
"""
from .client import N8nClient, N8nRequestFailed
from .response_parser import parse_response
from .route_resolver import NoRouteError, RouteMatch, RouteResolver

__all__ = [
    "N8nClient",
    "N8nRequestFailed",
    "NoRouteError",
    "RouteMatch",
    "RouteResolver",
    "parse_response",
]
```

- [ ] **Step 2: Verify imports work**

Run: `python -c "from tengen.n8n import RouteResolver, N8nClient, parse_response, RouteMatch, NoRouteError, N8nRequestFailed; print('OK')"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add tengen/n8n/__init__.py
git commit -m "feat(n8n): export public API from package init"
```

---

### Task 7: Rewrite router agent with n8n tools

**Files:**
- Modify: `tengen/agents/router.py`
- Create: `tests/test_router_n8n.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_router_n8n.py`:

```python
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
    assert router_agent.sub_agents == [] or router_agent.sub_agents is None or len(router_agent.sub_agents) == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_router_n8n.py -v`
Expected: FAIL — old router code still references runbook agents

- [ ] **Step 3: Rewrite router.py**

Replace `tengen/agents/router.py` with:

```python
"""RouterAgent — routes events to n8n workflows via webhook dispatch."""
from __future__ import annotations

import json
import logging

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

from ..config import settings
from ..n8n.client import N8nClient, N8nRequestFailed
from ..n8n.route_resolver import NoRouteError, RouteResolver

logger = logging.getLogger(__name__)

# Module-level singletons — initialized once, reused across invocations.
_route_resolver = RouteResolver(settings.n8n_routes_path)
_n8n_client = N8nClient(
    timeout=settings.n8n_timeout,
    max_retries=settings.n8n_max_retries,
    backoff_base=settings.n8n_backoff_base,
)


def _resolve_route(vendor: str, category: str, event_type: str | None = None) -> str:
    """Resolve a vendor/category/event_type to an n8n webhook URL.

    Consults the n8n routing spec YAML (auto-reloads on file change).
    Returns JSON: {"webhook_url": "...", "route_path": "...", "description": "..."}.
    On no match: {"error": "no_route", "vendor": "...", "category": "..."}.
    """
    try:
        match = _route_resolver.resolve(vendor, category, event_type)
        return json.dumps({
            "webhook_url": match.webhook_url,
            "route_path": match.route_path,
            "description": match.description,
        })
    except NoRouteError as exc:
        logger.error("No n8n route: %s", exc)
        return json.dumps({
            "error": "no_route",
            "vendor": vendor,
            "category": category,
            "event_type": event_type,
        })


def _execute_webhook(webhook_url: str, payload_json: str) -> str:
    """POST event payload to an n8n webhook and return the response.

    Returns the raw n8n JSON response as a string.
    On failure: {"error": "webhook_failed", "details": "...", "dlq": true}.
    """
    try:
        payload = json.loads(payload_json)
    except json.JSONDecodeError as exc:
        return json.dumps({"error": "invalid_payload", "details": str(exc)})

    try:
        result = _n8n_client.execute_sync(webhook_url, payload)
        return json.dumps(result)
    except N8nRequestFailed as exc:
        logger.error("n8n webhook failed: %s", exc)
        return json.dumps({
            "error": "webhook_failed",
            "details": str(exc),
            "url": exc.url,
            "status": exc.status,
            "attempts": exc.attempts,
            "dlq": True,
        })


router_agent = LlmAgent(
    name="router_agent",
    model=settings.model_name,
    description=(
        "Routes security events to the correct n8n workflow via webhook. "
        "Uses a hierarchical routing spec to match vendor/category/event_type to webhook URLs."
    ),
    instruction=(
        "You are the RouterAgent. You receive a security event or incident as JSON. "
        "Your job is to dispatch it to the correct n8n workflow for processing. "
        "\n"
        "1. Analyze the event to identify: "
        "   - vendor: the source platform (aws, crowdstrike, gcp, azure, k8s) "
        "   - category: the log type or subsystem (cloudtrail, windows, audit, signin) "
        "   - event_type: the specific event if identifiable (root_login, powershell_execution) "
        "\n"
        "2. Call resolve_route(vendor, category, event_type) to find the n8n webhook URL. "
        "   If it returns an error, use the catch-all default or route to DLQ. "
        "\n"
        "3. Call execute_webhook(webhook_url, payload_json) with the resolved URL "
        "   and the full event JSON as the payload. "
        "\n"
        "4. If the webhook succeeds, return the n8n response JSON. "
        "   If it fails (dlq=true in response), return the error JSON so the "
        "   orchestrator can route to the dead-letter queue. "
        "\n"
        "Do not modify the event payload. Pass it to n8n as-is."
    ),
    tools=[
        FunctionTool(func=_resolve_route),
        FunctionTool(func=_execute_webhook),
    ],
)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_router_n8n.py -v`
Expected: all 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add tengen/agents/router.py tests/test_router_n8n.py
git commit -m "feat(n8n): rewrite router agent with n8n webhook dispatch"
```

---

### Task 8: Rewrite orchestrator agent

**Files:**
- Modify: `tengen/agents/orchestrator.py`

- [ ] **Step 1: Rewrite orchestrator.py**

Replace `tengen/agents/orchestrator.py` with:

```python
"""OrchestratorAgent — top-level pipeline: ingest → normalize → triage → route (n8n) → forward."""
from __future__ import annotations

import json
import uuid

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

from ..config import settings
from .forwarder import forwarder_agent
from .normalizer import normalizer_agent
from .router import router_agent
from .triage import triage_agent


def _normalize_event(raw_event_json: str) -> str:
    """Normalize a raw log event into a NormalizedEvent JSON.

    Delegates to the normalizer registry for provider-specific parsing.
    Returns JSON string of the NormalizedEvent or an error dict.
    """
    from ..tools.normalizers.registry import normalize
    try:
        raw_event = json.loads(raw_event_json)
        normalized = normalize(raw_event)
        return normalized.model_dump_json()
    except Exception as exc:
        return json.dumps({"error": f"normalization_failed: {exc}", "raw_preview": raw_event_json[:200]})


def _validate_normalized_event(event_json: str) -> str:
    """Validate that a NormalizedEvent is processable. Returns 'valid' or 'invalid: <reason>'."""
    from ..models.normalized_event import NormalizedEvent
    try:
        event = NormalizedEvent.model_validate_json(event_json)
        if not event.source_type:
            return "invalid: missing source_type"
        if not event.event_id:
            return "invalid: missing event_id"
        return "valid"
    except Exception as exc:
        return f"invalid: {exc}"


def _emit_metric(event_name: str, data_json: str = "{}") -> str:
    """Emit a metric event for observability. Returns 'ok' or 'error: <msg>'."""
    try:
        from ..metrics.emitter import MetricsEmitter
        emitter = MetricsEmitter()
        data = json.loads(data_json) if data_json else {}
        emitter.emit(event_name, data)
        return "ok"
    except Exception as exc:
        return f"error: {exc}"


def _parse_n8n_response(n8n_response_json: str, original_event_json: str, route_path: str) -> str:
    """Parse the n8n webhook response into an EnrichedAlert JSON.

    Takes the raw n8n response, the original alert/event, and the route path.
    Returns an EnrichedAlert JSON string.
    """
    from ..models.alert import Alert
    from ..n8n.response_parser import parse_response
    try:
        n8n_data = json.loads(n8n_response_json)
        # Try to parse original as Alert; fall back to constructing one
        try:
            alert = Alert.model_validate_json(original_event_json)
        except Exception:
            raw = json.loads(original_event_json)
            alert = Alert(source="unknown", raw_payload=raw)
        enriched = parse_response(n8n_data, alert, route_path)
        return enriched.model_dump_json()
    except Exception as exc:
        return json.dumps({"error": f"parse_failed: {exc}"})


orchestrator_agent = LlmAgent(
    name="orchestrator_agent",
    model=settings.model_name,
    description=(
        "Top-level Tengen security orchestrator. "
        "Drives the pipeline: normalize → triage → route (n8n dispatch) → parse response → forward."
    ),
    instruction=(
        "You are the OrchestratorAgent for Tengen — a multi-cloud security harness. "
        "When given a raw security event JSON, execute the pipeline: "
        ""
        "STEP 1 — NORMALIZE: "
        "  Call normalize_event with the raw event JSON. "
        "  Call validate_normalized_event. If invalid, call emit_metric('normalization_error') "
        "  and return: {status: 'dropped', reason: <validation_error>}. "
        "  Call emit_metric('event_normalized', {source_type: <value>}). "
        ""
        "STEP 2 — TRIAGE: "
        "  Transfer to triage_agent with the NormalizedEvent JSON and incident_store '[]'. "
        "  Receive triage result: {suppressed, incident, score}. "
        "  If suppressed=true: call emit_metric('event_suppressed') and return "
        "  {status: 'suppressed', reason: <reason>}. "
        "  Call emit_metric('incident_created', {score: <score>}). "
        ""
        "STEP 3 — ROUTE TO n8n: "
        "  Transfer to router_agent with the event JSON. "
        "  The router will resolve the n8n webhook and dispatch the event. "
        "  Receive the n8n response JSON (or an error with dlq=true). "
        "  If dlq=true: call emit_metric('n8n_dispatch_failed') and note the error. "
        "  Otherwise: call emit_metric('n8n_dispatch_success'). "
        ""
        "STEP 4 — PARSE RESPONSE: "
        "  Call parse_n8n_response with the n8n response, original event, and route_path. "
        "  This produces an EnrichedAlert JSON. "
        ""
        "STEP 5 — FORWARD: "
        "  Transfer to forwarder_agent with the EnrichedAlert or Finding JSON. "
        ""
        "FINAL RESPONSE: Return a plain-text summary: "
        "  event_id, source_type, triage score, n8n route used, "
        "  enrichment status, forwarding status."
    ),
    tools=[
        FunctionTool(func=_normalize_event),
        FunctionTool(func=_validate_normalized_event),
        FunctionTool(func=_emit_metric),
        FunctionTool(func=_parse_n8n_response),
    ],
    sub_agents=[
        normalizer_agent,
        triage_agent,
        router_agent,
        forwarder_agent,
    ],
)
```

- [ ] **Step 2: Verify orchestrator imports cleanly**

Run: `N8N_ROUTES_PATH=tests/fixtures/n8n_routes.yaml python -c "from tengen.agents.orchestrator import orchestrator_agent; print(orchestrator_agent.name, len(orchestrator_agent.sub_agents), 'sub-agents')"`
Expected: `orchestrator_agent 4 sub-agents`

- [ ] **Step 3: Commit**

```bash
git add tengen/agents/orchestrator.py
git commit -m "feat(n8n): rewrite orchestrator to use n8n dispatch pipeline"
```

---

### Task 9: Delete replaced modules

**Files:**
- Delete: `tengen/agents/cloudtrail_runbook.py`
- Delete: `tengen/agents/gcp_audit_runbook.py`
- Delete: `tengen/agents/azure_runbook.py`
- Delete: `tengen/agents/edr_runbook.py`
- Delete: `tengen/agents/k8s_runbook.py`
- Delete: `tengen/agents/enrichment_agent.py`
- Delete: `tengen/agents/containment.py`
- Delete: `tengen/runbooks/` (entire directory)
- Delete: `tengen/enrichers/` (entire directory)
- Delete: `tengen/tools/enrichment.py`
- Delete: `tengen/tools/containment/` (entire directory)
- Delete: `tengen/mcp_servers/` (entire directory)
- Delete: `runbooks/` (top-level directory)

- [ ] **Step 1: Remove all replaced modules**

```bash
# Agents replaced by n8n
git rm tengen/agents/cloudtrail_runbook.py
git rm tengen/agents/gcp_audit_runbook.py
git rm tengen/agents/azure_runbook.py
git rm tengen/agents/edr_runbook.py
git rm tengen/agents/k8s_runbook.py
git rm tengen/agents/enrichment_agent.py
git rm tengen/agents/containment.py

# Runbook framework
git rm -r tengen/runbooks/

# Enricher pipeline
git rm -r tengen/enrichers/

# Tools replaced by n8n
git rm tengen/tools/enrichment.py
git rm -r tengen/tools/containment/

# MCP servers
git rm -r tengen/mcp_servers/

# Top-level runbook definitions
git rm -r runbooks/
```

- [ ] **Step 2: Remove stale test files that test deleted modules**

Check which test files reference deleted modules and remove them:

```bash
# Tests for deleted modules
git rm -f tests/test_enrichment.py
git rm -f tests/test_gcp_audit_runbook.py
# Remove old router test that references _detect_cloud_provider (no longer exists)
git rm -f tests/test_router.py
```

- [ ] **Step 3: Verify no broken imports remain**

Run: `N8N_ROUTES_PATH=tests/fixtures/n8n_routes.yaml python -c "from tengen.agents.orchestrator import orchestrator_agent; print('OK')"`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor: remove runbook agents, enrichers, MCP servers replaced by n8n"
```

---

### Task 10: Create sample routing spec

**Files:**
- Create: `n8n_routes.example.yaml`

- [ ] **Step 1: Create the example routing spec at repo root**

Create `n8n_routes.example.yaml`:

```yaml
# n8n Webhook Routing Spec
# ========================
# Mount as OpenShift ConfigMap at /etc/tengen/n8n_routes.yaml
# or set N8N_ROUTES_PATH env var to a custom path.
#
# Structure: vendor → category → event_type → webhook
# _default at every level catches unmatched events.
# description fields help the LLM router agent pick the right route.
#
# Update without redeployment:
#   oc create configmap tengen-n8n-routes \
#     --from-file=n8n_routes.yaml \
#     -o yaml --dry-run=client | oc apply -f -

version: "1"

routes:
  aws:
    description: "Amazon Web Services security events"
    cloudtrail:
      description: "CloudTrail API audit logs"
      root_login:
        webhook: https://n8n.example.com/webhook/aws-ct-root
        description: "Root account console or API activity"
      unauthorized_api:
        webhook: https://n8n.example.com/webhook/aws-ct-unauth
        description: "AccessDenied or UnauthorizedAccess events"
      _default:
        webhook: https://n8n.example.com/webhook/aws-ct-general
    guardduty:
      _default:
        webhook: https://n8n.example.com/webhook/aws-guardduty
    _default:
      webhook: https://n8n.example.com/webhook/aws-general

  crowdstrike:
    description: "CrowdStrike EDR detections"
    windows:
      powershell_execution:
        webhook: https://n8n.example.com/webhook/cs-win-powershell
        description: "Suspicious or unknown PowerShell execution"
      credential_access:
        webhook: https://n8n.example.com/webhook/cs-win-credaccess
        description: "Credential dumping or theft detections"
      _default:
        webhook: https://n8n.example.com/webhook/cs-windows
    linux:
      _default:
        webhook: https://n8n.example.com/webhook/cs-linux
    _default:
      webhook: https://n8n.example.com/webhook/cs-general

  gcp:
    description: "Google Cloud Platform security events"
    audit:
      admin_activity:
        webhook: https://n8n.example.com/webhook/gcp-admin
        description: "Admin Activity audit log events"
      data_access:
        webhook: https://n8n.example.com/webhook/gcp-data-access
        description: "Data Access audit log events"
      _default:
        webhook: https://n8n.example.com/webhook/gcp-audit
    _default:
      webhook: https://n8n.example.com/webhook/gcp-general

  azure:
    description: "Microsoft Azure security events"
    signin:
      risky_signin:
        webhook: https://n8n.example.com/webhook/azure-risky-signin
        description: "Risky sign-in detections from Azure AD"
      _default:
        webhook: https://n8n.example.com/webhook/azure-signin
    activity:
      privilege_escalation:
        webhook: https://n8n.example.com/webhook/azure-privesc
        description: "Role assignment or privilege escalation events"
      _default:
        webhook: https://n8n.example.com/webhook/azure-activity
    _default:
      webhook: https://n8n.example.com/webhook/azure-general

  k8s:
    description: "Kubernetes and OpenShift audit events"
    audit:
      privileged_container:
        webhook: https://n8n.example.com/webhook/k8s-privileged
        description: "Privileged container launch or escalation"
      secrets_access:
        webhook: https://n8n.example.com/webhook/k8s-secrets
        description: "Unusual secrets access patterns"
      anomalous_exec:
        webhook: https://n8n.example.com/webhook/k8s-exec
        description: "Anomalous exec into running containers"
      _default:
        webhook: https://n8n.example.com/webhook/k8s-audit
    _default:
      webhook: https://n8n.example.com/webhook/k8s-general

  _default:
    webhook: https://n8n.example.com/webhook/general-triage
    description: "Catch-all for unrecognized vendors or event types"
```

- [ ] **Step 2: Commit**

```bash
git add n8n_routes.example.yaml
git commit -m "docs: add example n8n routing spec"
```

---

### Task 11: Run all tests and verify

**Files:**
- No new files

- [ ] **Step 1: Run the full test suite**

Run: `N8N_ROUTES_PATH=tests/fixtures/n8n_routes.yaml python -m pytest tests/ -v --tb=short`

Expected: All new tests pass. Some pre-existing tests may need the env var or may reference deleted modules — fix any that fail.

- [ ] **Step 2: Fix any broken pre-existing tests**

If any remaining tests import deleted modules (e.g., `test_orchestrator.py` importing containment/enrichment agents), update them to work with the new architecture or remove them if they test deleted functionality.

- [ ] **Step 3: Final commit**

```bash
git add -A
git commit -m "test: fix remaining tests for n8n architecture"
```

# n8n Connector — Design Spec

**Date:** 2026-06-20
**Status:** Approved

## Summary

Replace Tengen's in-process runbook agents, enrichment pipeline, and containment tools with a webhook-based connector to n8n. n8n becomes the workflow engine for playbook execution, data enrichment, and triage response. Tengen retains ingestion, normalization, triage, and routing — then dispatches events to n8n via HTTP webhook and forwards the enriched results to Splunk.

## Architecture

```
Consumers (SQS/Kafka/PubSub/HTTP)
       │
       ▼
  Normalizer Agent
       │
       ▼
   Triage Agent (correlate, score, suppress)
       │
       ▼
   Router Agent
       │
       ├── resolve_route(vendor, category, event_type)
       │       └── reads n8n_routes.yaml (ConfigMap)
       │
       ├── execute_webhook(url, payload)
       │       └── POST to n8n, retry on failure
       │
       ├── on success: parse response → EnrichedAlert → Forwarder → Splunk
       └── on failure: DLQ with error metadata
```

## Communication Pattern

Synchronous webhook. Tengen POSTs the event to an n8n webhook URL, n8n executes the workflow, and returns the result in the HTTP response body.

## Boundary

| Tengen (keeps)                  | n8n (new)                          |
|---------------------------------|------------------------------------|
| Ingestion (consumers)           | Runbook/playbook execution         |
| Normalization                   | Data enrichment (IP, domain, etc.) |
| Triage (correlate, score, suppress) | Investigation steps            |
| Routing (vendor/category → URL) | Containment actions                |
| Forwarding (Splunk)             |                                    |

## Routing Strategy

Route by URL. Each source type/vendor/category maps to a dedicated n8n webhook URL. The LLM-based router agent reads the event, consults the routing spec YAML, and picks the most specific matching route.

### Routing Spec (`n8n_routes.yaml`)

Hierarchical YAML: `vendor → category → event_type → webhook`. `_default` at every level catches unmatched events. `description` fields help the LLM make routing decisions and serve as documentation.

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
      _default:
        webhook: https://n8n.example.com/webhook/cs-windows
    linux:
      _default:
        webhook: https://n8n.example.com/webhook/cs-linux
    _default:
      webhook: https://n8n.example.com/webhook/cs-general

  gcp:
    audit:
      admin_activity:
        webhook: https://n8n.example.com/webhook/gcp-admin
        description: "Admin Activity audit log events"
      _default:
        webhook: https://n8n.example.com/webhook/gcp-audit
    _default:
      webhook: https://n8n.example.com/webhook/gcp-general

  azure:
    signin:
      _default:
        webhook: https://n8n.example.com/webhook/azure-signin
    _default:
      webhook: https://n8n.example.com/webhook/azure-general

  k8s:
    audit:
      privileged_container:
        webhook: https://n8n.example.com/webhook/k8s-privileged
        description: "Privileged container launch or escalation"
      secrets_access:
        webhook: https://n8n.example.com/webhook/k8s-secrets
      _default:
        webhook: https://n8n.example.com/webhook/k8s-audit
    _default:
      webhook: https://n8n.example.com/webhook/k8s-general

  _default:
    webhook: https://n8n.example.com/webhook/general-triage
    description: "Catch-all for unrecognized vendors or event types"
```

### Deployment

The routing spec is mounted as an OpenShift **ConfigMap** at a configurable path (env var `N8N_ROUTES_PATH`, default `/etc/tengen/n8n_routes.yaml`). The route resolver watches file mtime and reloads on change — no pod restart required.

```yaml
# OpenShift deployment snippet
volumes:
  - name: n8n-routes
    configMap:
      name: tengen-n8n-routes

containers:
  - name: tengen
    volumeMounts:
      - name: n8n-routes
        mountPath: /etc/tengen
```

Update routes without redeployment:

```bash
oc create configmap tengen-n8n-routes \
  --from-file=n8n_routes.yaml \
  -o yaml --dry-run=client | oc apply -f -
```

## Package: `tengen/n8n/`

Three modules: `route_resolver.py`, `client.py`, `response_parser.py` (plus `__init__.py`).

### Configuration (`tengen/config.py`)

n8n settings added to the existing `Settings` dataclass in `tengen/config.py` (no separate config file):

| Setting | Env var | Default |
|---------|---------|---------|
| `n8n_routes_path` | `N8N_ROUTES_PATH` | `/etc/tengen/n8n_routes.yaml` |
| `n8n_timeout` | `N8N_TIMEOUT` | `30` (seconds) |
| `n8n_max_retries` | `N8N_MAX_RETRIES` | `3` |
| `n8n_backoff_base` | `N8N_BACKOFF_BASE` | `2` (seconds, exponential: 2s, 4s, 8s) |

### `tengen/n8n/route_resolver.py`

- Loads YAML into nested dict on startup
- Checks file mtime on each `resolve()` call — reloads if changed
- `resolve(vendor: str, category: str, event_type: str | None) -> RouteMatch`
- Walks tree from most-specific to least-specific, falls back through `_default`
- `RouteMatch` dataclass: `webhook_url: str`, `route_path: str`, `description: str`
- Raises `NoRouteError` if no match and no root `_default`

### `tengen/n8n/client.py`

- `N8nClient.execute(webhook_url: str, payload: dict) -> dict`
- POST with JSON body, returns parsed JSON response
- Uses `httpx` with connection pooling (single shared client instance)
- Retry on 5xx, timeout, connection error — up to `N8N_MAX_RETRIES` attempts
- Exponential backoff: `N8N_BACKOFF_BASE ** attempt` seconds
- No retry on 4xx (bad payload — not transient)
- Raises `N8nRequestFailed` on exhausted retries with last error details

### `tengen/n8n/response_parser.py`

- `parse_response(raw_response: dict, original_event: dict) -> EnrichedAlert`
- Preserves original event metadata (source_type, event_id, timestamps)
- Stuffs the entire n8n response into `enrichment` field
- Extracts well-known fields if present (severity, recommendations, IOCs) but does not require them
- On malformed response: returns partial `EnrichedAlert` with `enrichment_error` flag rather than failing

## ADK Tool Integration

### Router Agent (`tengen/agents/router.py`)

Two new `FunctionTool`s replace all runbook sub-agents:

**`resolve_route(vendor: str, category: str, event_type: str | None) -> str`**
- Wrapper around `route_resolver.resolve()`
- Returns JSON: `{"webhook_url": "...", "route_path": "...", "description": "..."}`
- On `NoRouteError`: `{"error": "no_route", "fallback": "<default webhook>"}`

**`execute_webhook(webhook_url: str, payload_json: str) -> str`**
- Wrapper around `N8nClient.execute()`
- Returns raw n8n JSON response as string
- On `N8nRequestFailed`: `{"error": "webhook_failed", "details": "...", "dlq": true}`

**Agent instruction:**
1. Read the incoming event and identify vendor, category, and event type
2. Call `resolve_route` to find the correct n8n webhook
3. Call `execute_webhook` with the resolved URL and event payload
4. If the webhook fails, forward the event to DLQ
5. If it succeeds, return the n8n response for downstream parsing and forwarding

### Orchestrator (`tengen/agents/orchestrator.py`)

- Removes `enrichment_agent` and `containment_agent` from sub-agent chain
- After router returns, orchestrator calls response parser to produce `EnrichedAlert`
- Pipeline: normalize → validate → triage → route (includes n8n dispatch) → parse response → forward

## Error Handling

```
webhook call
  ├── 2xx → parse response → EnrichedAlert → forwarder
  ├── 5xx / timeout / connection error → retry (up to 3, exponential backoff)
  │     └── all retries exhausted → DLQ with original event + error metadata
  ├── 4xx → no retry (bad payload) → DLQ with error details
  └── 2xx but unparseable body → partial EnrichedAlert with enrichment_error flag → forwarder
```

DLQ events include:
- Original event payload
- Attempted webhook URL
- Route path
- Error type and message
- Timestamp
- Attempt count

The forwarder handles `enrichment_error`-flagged alerts normally — they still reach Splunk with whatever data was available, and the error flag is searchable.

## Response Contract

n8n returns freeform JSON. Tengen does not impose schema requirements on n8n workflows. The response parser maps the response into `EnrichedAlert`:

- `enrichment` field: entire n8n response (preserved verbatim)
- Well-known fields extracted if present: `severity`, `recommendations`, `iocs`, `verdict`
- Original event metadata preserved from the inbound event
- `enrichment_error: bool` flag set on parse failures

## Modules Removed

| Path | Reason |
|------|--------|
| `tengen/agents/cloudtrail_runbook.py` | Replaced by n8n workflow |
| `tengen/agents/gcp_audit_runbook.py` | Replaced by n8n workflow |
| `tengen/agents/azure_runbook.py` | Replaced by n8n workflow |
| `tengen/agents/edr_runbook.py` | Replaced by n8n workflow |
| `tengen/agents/k8s_runbook.py` | Replaced by n8n workflow |
| `tengen/agents/enrichment_agent.py` | Enrichment moves to n8n |
| `tengen/agents/containment.py` | Containment moves to n8n |
| `tengen/runbooks/` (entire package) | BaseRunbook + subclasses replaced |
| `tengen/enrichers/` (entire package) | Enricher pipeline replaced |
| `tengen/tools/enrichment.py` | Lookup tools replaced |
| `tengen/tools/containment/` | Containment tools replaced |
| `tengen/mcp_servers/` | MCP servers replaced |
| `runbooks/` (top-level YAML) | Runbook definitions replaced by `n8n_routes.yaml` |

## Modules Modified

| Path | Change |
|------|--------|
| `tengen/agents/router.py` | Drop runbook sub-agents, add `resolve_route` + `execute_webhook` tools |
| `tengen/agents/orchestrator.py` | Remove enrichment/containment from pipeline, add response parsing |
| `tengen/config.py` | Add n8n settings |

## Modules Untouched

- `tengen/consumers/` — all consumers
- `tengen/agents/normalizer.py`
- `tengen/agents/triage.py`
- `tengen/forwarder/`
- `tengen/models/`
- `tengen/routing/`
- `tengen/tools/triage_tools.py`
- `tengen/tools/alert_parser.py`
- `tengen/tools/normalizers/`
- `tengen/dashboard/`
- `tengen/tui/`
- `tengen/metrics/`

## New Dependency

- `httpx` — async-capable HTTP client with connection pooling and retry support

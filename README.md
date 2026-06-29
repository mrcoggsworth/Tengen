# Tengen — Agentic Security Harness

Tengen is a production-grade, multi-cloud security agentic harness built on [Google ADK](https://google.github.io/adk-docs/). It ingests security events from any cloud provider or EDR platform, normalizes them into a universal schema, triages and correlates them into incidents, dispatches them to n8n workflows via webhook for playbook execution and enrichment, and forwards results to your SIEM — all driven by LLM agents coordinated through a durable RabbitMQ event backbone.

Tengen is the spiritual successor to [LogPose](https://github.com/mrcoggsworth/LogPose), combining LogPose's production infrastructure (durable queuing, consumer pods, dashboard, forwarder) with an LLM agentic layer for reasoning, n8n workflow orchestration, and decision-making.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Agent Pipeline](#agent-pipeline)
- [Project Structure](#project-structure)
- [Supported Log Sources](#supported-log-sources)
- [Models](#models)
- [Consumers](#consumers)
- [Queue System](#queue-system)
- [Normalization](#normalization)
- [Triage and Correlation](#triage-and-correlation)
- [Routing](#routing)
- [n8n Connector](#n8n-connector)
- [n8n Routing Spec](#n8n-routing-spec)
- [Query Agent](#query-agent)
- [Forwarder](#forwarder)
- [Dashboard](#dashboard)
- [Metrics](#metrics)
- [Configuration](#configuration)
- [Quick Start](#quick-start)
- [Docker Compose](#docker-compose)
- [Entry Points](#entry-points)
- [Running Tests](#running-tests)
- [Extending Tengen](#extending-tengen)

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│  PHASE 1 — INGESTION                                                      │
│                                                                           │
│  Kafka   SQS/SNS   Pub/Sub   Splunk ES   Universal HTTP   Direct inject  │
│     └─────────────────────────────────────┘                              │
│                         ↓                                                 │
│                 RabbitMQ [alerts] queue                                   │
└──────────────────────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────────────────┐
│  PHASE 2 — NORMALIZATION  (NormalizerAgent)                               │
│                                                                           │
│  detect_source_type() → per-source normalizer → NormalizedEvent          │
│  Sources: aws · gcp · azure · crowdstrike · k8s · firewall · ddos        │
│                         ↓                                                 │
│                 RabbitMQ [normalized] queue                               │
└──────────────────────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────────────────┐
│  PHASE 3 — TRIAGE  (TriageAgent)                                          │
│                                                                           │
│  correlate_event()   → 15-min rolling window, group by actor+source      │
│  score_incident()    → severity × source_weight × recurrence_factor      │
│  check_suppression() → known-good, below threshold, info-only noise      │
│                                                                           │
│  suppressed → [alerts.dlq]      active → [incidents] queue               │
└──────────────────────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────────────────┐
│  PHASE 4 — ROUTING via n8n  (RouterAgent)                                 │
│                                                                           │
│  resolve_route(vendor, category, event_type)                              │
│    → hierarchical YAML lookup → n8n webhook URL                          │
│  execute_webhook(url, payload)                                            │
│    → POST event to n8n → receive response JSON                           │
│                                                                           │
│  no route → [alerts.dlq]        matched → n8n webhook dispatch           │
└──────────────────────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────────────────┐
│  PHASE 5 — n8n WORKFLOW EXECUTION  (external)                             │
│                                                                           │
│  Runs in n8n — playbook execution, enrichment, containment,              │
│  threat intelligence lookups, and any custom automation.                  │
│  Returns freeform JSON response to Tengen.                               │
└──────────────────────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────────────────┐
│  PHASE 6 — RESPONSE PARSING  (OrchestratorAgent)                          │
│                                                                           │
│  parse_n8n_response() → maps freeform JSON to EnrichedAlert              │
│  Extracts well-known fields: severity, recommendations, iocs, verdict    │
│  Sets enrichment_error=true on empty/malformed responses                 │
│                         ↓                                                 │
│                 RabbitMQ [enriched] queue                                 │
└──────────────────────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────────────────┐
│  PHASE 7 — FORWARDING                                                     │
│                                                                           │
│  EnrichedAlertForwarder → Splunk HEC (batched, retrying, exp. backoff)   │
│  DLQForwarder           → Splunk HEC (sourcetype: tengen:dlq)            │
│  ForwarderAgent         → PagerDuty Events v2 (HIGH/CRITICAL only)       │
└──────────────────────────────────────────────────────────────────────────┘

QueryAgent ──────── ad-hoc analyst NL queries across all sources ──────────
                    CloudTrail · GCP · Azure · CrowdStrike · K8s
                    Cross-source IP correlation

Dashboard ──────── FastAPI + browser UI  http://localhost:8080 ────────────
                   Live queue depths · route counts · n8n dispatch stats
                   normalization rates · DLQ depth

MetricsEmitter ─── fire-and-forget throughout every phase ─────────────────
                   → [tengen.metrics] → MetricsStore (SQLite) → Dashboard
```

---

## Agent Pipeline

### OrchestratorAgent (`tengen/agents/orchestrator.py`)
The top-level coordinator. Drives the complete 5-step pipeline for every event: normalize → triage → route (n8n dispatch) → parse response → forward. Instruments each phase with `MetricsEmitter`. If any step fails, it records the failure and continues where possible rather than dropping the event.

**Tools:** `normalize_event`, `validate_normalized_event`, `emit_metric`, `parse_n8n_response`
**Sub-agents:** NormalizerAgent, TriageAgent, RouterAgent, ForwarderAgent

### NormalizerAgent (`tengen/agents/normalizer.py`)
Detects the log source type and normalizes raw events into the universal `NormalizedEvent` schema. Supports all 8 source types. Returns the NormalizedEvent JSON or an error JSON if normalization fails.

**Tools:** `detect_source_type`, `detect_and_normalize`

### TriageAgent (`tengen/agents/triage.py`)
Receives a NormalizedEvent and an in-memory incident store. Correlates the event into an existing open Incident (same actor + same source type within a 15-minute window) or creates a new one. Computes a priority score. Checks suppression rules. Returns a structured result indicating whether the incident should proceed or be suppressed.

**Tools:** `correlate_event`, `score_incident`, `check_suppression`, `update_incident_score`

### RouterAgent (`tengen/agents/router.py`)
Dispatches security events to n8n workflows via webhook. Analyzes the event to identify vendor, category, and event type, then resolves the matching n8n webhook URL from the hierarchical routing spec. Executes the webhook and returns the n8n response JSON. Unroutable events are sent to the dead-letter queue.

**Tools:** `resolve_route`, `execute_webhook`

### QueryAgent (`tengen/agents/query.py`)
Analyst-facing agent for ad-hoc natural-language security queries. Translates NL questions into targeted API calls across all available data sources. Returns a markdown summary table, key observations, and recommended next actions.

**Tools:** `query_cloudtrail`, `query_cloudtrail_by_ip`, `query_gcp_audit`, `query_azure_activity`, `query_crowdstrike_detections`, `query_k8s_events`, `correlate_ip_across_sources`

### ForwarderAgent (`tengen/agents/forwarder.py`)
Receives enriched Finding JSON. Routes to Splunk HEC for all severities and to PagerDuty for HIGH/CRITICAL. Returns forwarding status.

---

## Project Structure

```
Tengen/
├── Dockerfile                          # Production container image
├── pyproject.toml                      # Package metadata + dependencies
├── .env.example                        # All configuration variables with descriptions
├── n8n_routes.example.yaml             # Example n8n routing spec
│
├── docker/
│   └── docker-compose.yml              # RabbitMQ, Kafka, LocalStack, Pub/Sub emulator
│
├── tengen/
│   ├── config.py                       # All settings (dataclass, reads from env)
│   ├── router_main.py                  # Entry point: start the routing pipeline
│   ├── forwarder_main.py               # Entry point: start enriched + DLQ forwarders
│   ├── dashboard_main.py               # Entry point: start the FastAPI dashboard
│   ├── udm_main.py                     # Entry point: tengen-udm CLI (parse/fields/branch)
│   │
│   ├── agents/                         # All LlmAgent definitions
│   │   ├── orchestrator.py             # Top-level 5-step pipeline coordinator
│   │   ├── normalizer.py               # NormalizerAgent
│   │   ├── triage.py                   # TriageAgent
│   │   ├── router.py                   # RouterAgent (n8n webhook dispatch)
│   │   ├── query.py                    # QueryAgent (analyst-facing NL queries)
│   │   └── forwarder.py                # ForwarderAgent (Splunk + PagerDuty)
│   │
│   ├── n8n/                            # n8n webhook integration
│   │   ├── __init__.py                 # Package exports
│   │   ├── route_resolver.py           # RouteResolver: hierarchical YAML → webhook URL
│   │   ├── client.py                   # N8nClient: HTTP POST with retry + exp. backoff
│   │   └── response_parser.py          # parse_response: freeform JSON → EnrichedAlert
│   │
│   ├── consumers/                      # Event ingestion layer
│   │   ├── base.py                     # BaseConsumer ABC (connect/consume/disconnect)
│   │   ├── sqs_consumer.py             # AWS SQS long-poll + SNS envelope unwrap
│   │   ├── kafka_consumer.py           # Confluent Kafka consumer
│   │   ├── pubsub_consumer.py          # GCP Pub/Sub pull subscription
│   │   ├── splunk_es_consumer.py       # Splunk ES notable event poller
│   │   └── universal_consumer.py       # FastAPI POST /ingest (Bearer auth)
│   │
│   ├── queue/                          # RabbitMQ abstraction
│   │   ├── queues.py                   # All queue name constants
│   │   ├── rabbitmq.py                 # RabbitMQPublisher (shared connection)
│   │   └── rabbitmq_consumer.py        # RabbitMQConsumer (ack/nack on result)
│   │
│   ├── models/                         # Pydantic v2 frozen data models
│   │   ├── alert.py                    # Alert, AlertSeverity, CloudProvider
│   │   ├── normalized_event.py         # NormalizedEvent, LogSourceType, ActorContext,
│   │   │                               #   TargetContext, NetworkContext, Outcome, to_udm()
│   │   ├── udm.py                      # UDMEvent + Metadata/Noun/User/Process/File/
│   │   │                               #   Network/SecurityResult + UDM enums
│   │   ├── incident.py                 # Incident, IncidentStatus
│   │   ├── finding.py                  # Finding, RemediationStep
│   │   ├── enriched_alert.py           # EnrichedAlert (n8n output with enrichment fields)
│   │   └── runbook.py                  # Runbook, RunbookStep
│   │
│   ├── udm/                            # UDM parsing + field-discovery layer
│   │   ├── parser.py                   # UDMParser: raw → UDMEvent + unmapped fields
│   │   ├── mappings.py                 # CONSUMED_PATHS + UDM-field suggestion heuristics
│   │   ├── field_registry.py           # FieldRegistry (separate low-resource SQLite DB)
│   │   └── model_updater.py            # Approved fields → proposal scaffold + branch
│   │
│   ├── routing/                        # Deterministic event routing
│   │   ├── registry.py                 # RouteRegistry + Route + MatcherFn
│   │   ├── router.py                   # Router pod (consumes [alerts], publishes to queues)
│   │   └── routes/                     # Auto-registered route matchers
│   │       ├── cloud/aws/cloudtrail.py
│   │       ├── cloud/aws/guardduty.py
│   │       ├── cloud/aws/eks.py
│   │       ├── cloud/gcp/event_audit.py
│   │       ├── cloud/azure/activity.py
│   │       ├── edr/crowdstrike.py
│   │       ├── k8s/audit.py
│   │       └── network/firewall.py
│   │
│   ├── tools/                          # Pure-Python tool functions
│   │   ├── alert_parser.py             # parse_cloudtrail_event, parse_gcp_audit_event
│   │   ├── triage_tools.py             # correlate_event, score_incident, check_suppression
│   │   ├── runbook_loader.py           # list_runbooks, load_runbook (YAML loader)
│   │   ├── forwarder_tools.py          # forward_to_siem, forward_to_pagerduty
│   │   └── normalizers/
│   │       ├── registry.py             # detect_source_type() + normalize() dispatch
│   │       ├── aws_normalizer.py       # CloudTrail → NormalizedEvent
│   │       ├── gcp_normalizer.py       # GCP Audit → NormalizedEvent
│   │       ├── azure_normalizer.py     # Azure Activity → NormalizedEvent
│   │       ├── crowdstrike_normalizer.py  # CS Detection → NormalizedEvent
│   │       ├── firewall_normalizer.py  # Firewall deny → NormalizedEvent
│   │       ├── ddos_normalizer.py      # DDoS flow → NormalizedEvent
│   │       └── k8s_normalizer.py       # K8s audit → NormalizedEvent (OpenShift aware)
│   │
│   ├── metrics/
│   │   └── emitter.py                  # MetricsEmitter (fire-and-forget, never raises)
│   │
│   ├── forwarder/
│   │   ├── splunk_client.py            # SplunkHECClient (batched, retrying, exp backoff)
│   │   ├── enriched_forwarder.py       # Drains [enriched] → Splunk HEC
│   │   └── dlq_forwarder.py            # Drains [alerts.dlq] → Splunk HEC
│   │
│   └── dashboard/
│       ├── app.py                      # FastAPI app with lifespan management
│       ├── metrics_store.py            # MetricsStore (thread-safe SQLite, 60s flush)
│       ├── metrics_consumer.py         # Background thread draining [tengen.metrics]
│       ├── rabbitmq_api.py             # RabbitMQ Management API client
│       ├── routes_reader.py            # RouteRegistry introspection for dashboard
│       └── static/index.html           # Dark-themed SPA (polls /api/* every 10s)
│
└── tests/
    ├── test_route_resolver.py          # n8n route resolver (9 tests)
    ├── test_n8n_client.py              # n8n HTTP client (7 tests)
    ├── test_response_parser.py         # n8n response parser (6 tests)
    ├── test_enriched_alert.py          # EnrichedAlert model (4 tests)
    ├── test_router_n8n.py              # Router agent n8n integration (6 tests)
    ├── test_normalizers.py             # Source detection + all 7 normalizers
    ├── test_triage.py                  # Correlation, scoring, suppression
    ├── test_models.py                  # Pydantic model validation
    ├── test_forwarder.py               # Forwarder tests
    ├── test_tools.py                   # Alert parser
    ├── test_udm_model.py               # UDM model tests
    ├── test_udm_parser.py              # UDM parser tests
    ├── test_field_registry.py          # Field registry tests
    ├── test_model_updater.py           # Model updater tests
    └── test_dashboard_udm.py           # Dashboard UDM endpoint tests
```

---

## Supported Log Sources

| Source | Normalizer | Route Matcher | n8n Route |
|---|---|---|---|
| AWS CloudTrail | `aws_normalizer.py` | `routes/cloud/aws/cloudtrail.py` | `aws.cloudtrail._default` |
| AWS GuardDuty | `aws_normalizer.py` | `routes/cloud/aws/guardduty.py` | `aws.guardduty._default` |
| AWS EKS | `aws_normalizer.py` | `routes/cloud/aws/eks.py` | `aws.eks._default` |
| GCP Audit Log | `gcp_normalizer.py` | `routes/cloud/gcp/event_audit.py` | `gcp.audit._default` |
| Azure Activity | `azure_normalizer.py` | `routes/cloud/azure/activity.py` | `azure.activity._default` |
| CrowdStrike EDR | `crowdstrike_normalizer.py` | `routes/edr/crowdstrike.py` | `crowdstrike.windows._default` |
| Kubernetes Audit | `k8s_normalizer.py` | `routes/k8s/audit.py` | `k8s.audit._default` |
| OpenShift Audit | `k8s_normalizer.py` | `routes/k8s/audit.py` | `k8s.audit._default` |
| Firewall Deny | `firewall_normalizer.py` | `routes/network/firewall.py` | `network.firewall._default` |
| DDoS Flow | `ddos_normalizer.py` | `routes/network/firewall.py` | `network.ddos._default` |

---

## Models

All models are **frozen Pydantic v2** (`model_config = {"frozen": True}`), meaning they are immutable after construction. This ensures safe concurrent use throughout the pipeline.

### `Alert` (`tengen/models/alert.py`)
The raw transport envelope produced by consumer pods before normalization.

| Field | Type | Description |
|---|---|---|
| `id` | `str` (UUID) | Unique alert ID |
| `source` | `str` | Transport source: `"sqs"`, `"kafka"`, `"pubsub"`, `"universal"` |
| `received_at` | `datetime` | UTC timestamp when the alert was received |
| `raw_payload` | `dict` | Raw event payload as received from the source |
| `metadata` | `dict` | Consumer metadata (queue name, message ID, etc.) |
| `alert_id` | `str` (UUID) | Legacy field, kept for backwards compatibility |
| `severity` | `AlertSeverity` | Legacy severity field |
| `event_type` | `str` | Legacy event type field |

### `NormalizedEvent` (`tengen/models/normalized_event.py`)
The universal event schema produced by normalizers. All downstream components work with this model.

| Field | Type | Description |
|---|---|---|
| `event_id` | `str` (UUID) | Unique event ID |
| `timestamp` | `str` | ISO 8601 event timestamp |
| `source_type` | `LogSourceType` | `aws`, `gcp`, `azure`, `crowdstrike`, `k8s`, `openshift`, `firewall`, `ddos`, `unknown` |
| `log_type` | `str` | Specific log format: `cloudtrail`, `gcp_audit`, `azure_activity`, `cs_detection`, etc. |
| `actor` | `ActorContext` | Identity making the action |
| `target` | `TargetContext` | Resource being acted upon |
| `network` | `NetworkContext` | Network context (IPs, ports, protocol) |
| `outcome` | `Outcome` | `success`, `failure`, `unknown` |
| `event_name` | `str` | Normalized action name |
| `severity` | `AlertSeverity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `raw_event` | `dict` | Original raw event (preserved for n8n workflow access) |
| `tags` | `list[str]` | Classification tags (tactic, technique, provider) |
| `labels` | `dict[str, str]` | Key-value metadata for filtering |
| `vendor_name` | `str` | UDM-aligned vendor (optional; defaulted in `to_udm()`) |
| `product_name` | `str` | UDM-aligned product (optional; defaulted in `to_udm()`) |
| `udm_event_type` | `UDMEventType \| None` | Explicit UDM event classification (optional) |

`NormalizedEvent.to_udm()` projects this event onto a `UDMEvent` (see
[Unified Data Model](#unified-data-model-udm--field-discovery)).

**Sub-models:**

`ActorContext`: `identity` (email/ARN/username), `identity_type`, `account_id`, `is_privileged`, `assumed_role`

`TargetContext`: `resource_id`, `resource_name`, `resource_type`, `namespace`, `hostname`, `region`, `project_id`

`NetworkContext`: `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `bytes_sent`, `packets_per_second`

### `Incident` (`tengen/models/incident.py`)
A correlated group of NormalizedEvents representing a single security incident.

| Field | Type | Description |
|---|---|---|
| `incident_id` | `str` (UUID) | Unique incident ID |
| `events` | `list[NormalizedEvent]` | All correlated events |
| `findings` | `list[Finding]` | Findings produced by n8n workflows |
| `status` | `IncidentStatus` | `open`, `triaging`, `contained`, `closed`, `suppressed` |
| `priority_score` | `float` | Computed priority score |
| `suppressed` | `bool` | Whether this incident has been suppressed |
| `suppression_reason` | `str` | Why it was suppressed |
| `created_at` | `str` | ISO 8601 creation time |
| `updated_at` | `str` | ISO 8601 last update time |
| `labels` | `dict[str, str]` | Metadata labels |

### `Finding` (`tengen/models/finding.py`)
The output of an n8n workflow investigation. Contains the full investigative result and remediation guidance.

| Field | Type | Description |
|---|---|---|
| `finding_id` | `str` (UUID) | Unique finding ID |
| `alert_id` | `str` | Source alert ID |
| `source` | `str` | Cloud/EDR source |
| `severity` | `AlertSeverity` | Finding severity |
| `title` | `str` | Human-readable title |
| `description` | `str` | Full investigation narrative |
| `remediation_steps` | `list[RemediationStep]` | Ordered remediation actions |
| `enrichment` | `dict` | All enrichment data (IPs, hashes, user info, asset info) |

### `EnrichedAlert` (`tengen/models/enriched_alert.py`)
Alert after n8n workflow processing. Published to the enriched queue for forwarding.

| Field | Type | Description |
|---|---|---|
| `alert` | `Alert` | Original alert (embedded unchanged) |
| `runbook` | `str` | Dot-separated identifier (e.g. `n8n.aws.cloudtrail`) |
| `enriched_at` | `datetime` | UTC timestamp of enrichment |
| `extracted` | `dict` | Well-known fields extracted from n8n response (severity, recommendations, iocs, verdict) |
| `runbook_error` | `str \| None` | Error message if n8n workflow failed |
| `destination` | `Literal` | `"splunk"`, `"universal"`, or `"pagerduty"` |
| `enrichment` | `dict` | Full n8n response payload |
| `enrichment_error` | `bool` | `True` if n8n returned empty/malformed response |
| `n8n_route_path` | `str` | Route path used (e.g. `aws.cloudtrail.root_login`) |

---

## Consumers

All consumers extend `BaseConsumer` (`tengen/consumers/base.py`) which defines:
- `connect()` / `disconnect()` — lifecycle management
- `consume(callback)` — blocking consume loop
- Context manager support (`async with`)
- Auto-retry with exponential backoff on connection failures

### SqsConsumer (`tengen/consumers/sqs_consumer.py`)
Long-polls an AWS SQS queue. Automatically unwraps SNS envelope payloads. Deletes messages on successful processing; leaves them in the queue on failure for DLQ routing. Configurable via `SQS_QUEUE_URL` and `AWS_REGION`.

### KafkaConsumer (`tengen/consumers/kafka_consumer.py`)
Confluent Kafka consumer. Supports multiple topics via comma-separated `KAFKA_TOPICS`. Commits offsets only on successful message processing. Configurable via `KAFKA_BOOTSTRAP_SERVERS`, `KAFKA_GROUP_ID`, `KAFKA_TOPICS`.

### PubSubConsumer (`tengen/consumers/pubsub_consumer.py`)
GCP Pub/Sub pull subscription consumer. Acks messages on success, nacks on failure. Supports the Pub/Sub emulator for local development via `PUBSUB_EMULATOR_HOST`. Configurable via `PUBSUB_PROJECT_ID`, `PUBSUB_SUBSCRIPTION_ID`.

### SplunkESConsumer (`tengen/consumers/splunk_es_consumer.py`)
Polls Splunk Enterprise Security for notable events on a configurable interval. Uses the Splunk REST API with token authentication. Configurable via `SPLUNK_ES_HOST`, `SPLUNK_ES_PORT`, `SPLUNK_ES_TOKEN`, `SPLUNK_ES_SEARCH`.

### UniversalHTTPConsumer (`tengen/consumers/universal_consumer.py`)
FastAPI-based HTTP ingest endpoint. Accepts any JSON payload at `POST /ingest`. Supports optional Bearer token authentication. Publishes received events directly to the `[alerts]` RabbitMQ queue. Configurable via `UNIVERSAL_HTTP_HOST`, `UNIVERSAL_HTTP_PORT`, `UNIVERSAL_HTTP_TOKEN`.

---

## Queue System

All queue name constants are defined in `tengen/queue/queues.py` — the single source of truth:

| Queue | Purpose |
|---|---|
| `alerts` | Raw events from all consumers |
| `normalized` | NormalizedEvent objects after normalization |
| `incidents` | Scored, non-suppressed Incidents ready for routing |
| `enriched` | Enriched alerts ready for forwarding |
| `alerts.dlq` | Dead-letter queue: unroutable or failed events |
| `tengen.metrics` | Metrics events (fire-and-forget) |

### RabbitMQPublisher (`tengen/queue/rabbitmq.py`)
Manages a shared pika connection. Declares queues as durable on first use. Fire-and-forget publish with optional `delivery_mode=2` (persistent messages). Never raises on failure — logs errors and continues.

### RabbitMQConsumer (`tengen/queue/rabbitmq_consumer.py`)
Blocking consumer with manual ack. Deserializes `Alert` objects from message bodies. Calls `ack` on successful processing, `nack` (no requeue) on failure to route to DLQ.

---

## Normalization

### Source Detection (`tengen/tools/normalizers/registry.py`)
`detect_source_type(raw: dict) -> LogSourceType` uses heuristics to identify the log source:

| Heuristic | Source |
|---|---|
| `eventSource` ends with `.amazonaws.com` + `eventVersion` present | AWS |
| `detail-type == "GuardDuty Finding"` | AWS |
| `"cloudaudit.googleapis.com"` in `logName` | GCP |
| `operationName.value` starts with `"Microsoft."` or `tenantId` present | Azure |
| `event_type` in `("DetectionSummaryEvent", "EppDetectionSummaryEvent")` | CrowdStrike |
| `FalconHostLink` in `Behaviors` | CrowdStrike |
| `apiVersion` is `"audit.k8s.io/v1"` or `"audit.k8s.io/v1beta1"` | K8s |
| `requestURI` + `objectRef` + `userAgent` all present | K8s |
| `apiVersion` ends with `openshift.io/v1` | OpenShift |
| `action` in `("DENY", "DROP", "BLOCK", "REJECT")` | Firewall |
| `attack_vector` or `pps` (packets per second) present | DDoS |

`normalize(raw: dict) -> NormalizedEvent` dispatches to the correct normalizer based on detected source type.

### Priority Score Formula
```
score = max_severity_score × source_weight × recurrence_factor

severity_scores:  CRITICAL=10.0, HIGH=7.0, MEDIUM=4.0, LOW=2.0, INFO=0.5
source_weights:   crowdstrike=1.5, k8s/openshift=1.3, aws/gcp/azure=1.2,
                  ddos=1.0, firewall=0.9, unknown=0.5
recurrence_factor = min(1.0 + (event_count - 1) × 0.2, 3.0)
privileged_actor_bonus: recurrence_factor × 1.5
```

Example: A single CRITICAL CrowdStrike event from a privileged account:
`10.0 × 1.5 × 1.0 × 1.5 = 22.5`

---

## Unified Data Model (UDM) & Field Discovery

Tengen parses every incoming alert into a single vendor-neutral schema modeled
on [Google Chronicle's Unified Data Model](https://cloud.google.com/chronicle/docs/event-processing/udm-overview),
so disparate terms (`sourceIPAddress`, `callerIp`, `clientIpAddress`, `LocalIP`)
all collapse onto the same UDM field (`principal.ip` / `src.ip`).

### `UDMEvent` (`tengen/models/udm.py`)
The canonical schema. A high-value subset of UDM with an `additional` escape
hatch that preserves anything not yet promoted to a first-class field.

| Section | Type | Maps from |
|---|---|---|
| `metadata` | `Metadata` | `event_timestamp`, `event_type` (UDM enum), `product_event_type`, `vendor_name`, `product_name`, `log_type` |
| `principal` | `Noun` | The actor (Tengen `ActorContext`) + source IP/port |
| `src` | `Noun` | Network-level source |
| `target` | `Noun` | Resource acted upon (Tengen `TargetContext`) + destination IP/port |
| `intermediary` / `observer` / `about` | `Noun` | Proxies, passive monitors, referenced entities |
| `network` | `Network` | Protocol, bytes, HTTP sub-record |
| `security_result` | `list[SecurityResult]` | Severity, action, rule/threat classification |
| `additional` | `dict` | Unmapped raw fields (preserved, never dropped) |

A **`Noun`** is the reused entity shape (`hostname`, `ip`, `port`, `mac`,
`user`, `process`, `file`, `registry`, `resource`, `cloud`, `location`,
`namespace`, `labels`, …). `NormalizedEvent` is UDM-aligned and exposes
`to_udm()` to project itself onto a `UDMEvent` — existing fields that already
fit UDM (`actor`→`principal`, `target`→`target`, `network`→`network`,
`outcome`/`severity`→`security_result`) are preserved.

### Parser (`tengen/udm/parser.py`)
`UDMParser.parse(raw)` runs the matching source normalizer, projects the result
to a `UDMEvent`, then walks the raw payload to find any leaf field the model
does not yet cover. Each unmapped field is preserved under
`additional.unmapped` and recorded in the **field registry** with a heuristic
suggestion (`tengen/udm/mappings.py`) for the UDM field it should map onto.

### Field registry (`tengen/udm/field_registry.py`)
A deliberately **low-resource, separate SQLite database** (one file, no server;
set via `TENGEN_UDM_REGISTRY_DB`, default `/tmp/tengen_udm_fields.db`) — kept
apart from the metrics DB. Each row is a discovered field candidate
(`source_type`, `raw_path`, `suggested_udm_field`, `value_type`,
`sample_value`, `occurrence_count`, `status`, `first_seen`/`last_seen`). Repeats
upsert and bump the counter. Status lifecycle: `new → approved → promoted`, or
`ignored`.

### Dashboard ("UDM Field Discovery")
The registry is surfaced in the front-end monitoring dashboard
(`tengen/dashboard`):

- `GET /api/udm/fields[?status=&source_type=]` — list candidates
- `GET /api/udm/fields/summary` — counts by status/source
- `PATCH /api/udm/fields/{id}` — review action (`approved` / `ignored` / re-map)

The dashboard renders a table with **Approve / Ignore** buttons, and the
overview adds a `UDM New Fields` stat card.

### Model updates via branch + PR (`tengen/udm/model_updater.py`)
Once an analyst approves fields, `propose_from_registry()` turns approved rows
into `FieldProposal`s (target model + field name + type, flagging new vs
already-existing). `create_update_branch()` writes a reviewable scaffold module
(`tengen/models/udm_proposed_fields.py`, `*Additions` classes), creates a new
branch, and commits it — **it never opens a PR automatically and never mutates
the live model**; a human folds the fields into `udm.py` and opens the PR after
review.

### `tengen-udm` CLI (`tengen/udm_main.py`)
```bash
cat alert.json | tengen-udm parse          # parse → UDM, record new fields
tengen-udm fields --status new             # list discovered candidates
tengen-udm summary                         # registry counts
tengen-udm approve 12                       # review actions
tengen-udm ignore 7
tengen-udm propose                          # preview proposal table + scaffold
tengen-udm branch                           # branch + commit scaffold (no PR)
```

---

## Triage and Correlation

### `correlate_event(event_json, incident_store_json) -> str`
Groups a NormalizedEvent into an existing open Incident or creates a new one. Matching criteria: same `actor.identity` + same `source_type` within a 15-minute rolling window. Skips CLOSED and SUPPRESSED incidents.

### `score_incident(incident_json) -> float`
Computes a priority score using the formula above. Score is capped at `max_severity × source_weight × 3.0 × 1.5` for privileged actors.

### `check_suppression(incident_json, suppression_rules_json) -> str`
Returns `{"suppressed": bool, "reason": str}`. Built-in rules:

1. **Below minimum score** — `priority_score < min_priority_score` (default: 1.0)
2. **Known-good identity** — actor identity appears in `known_good_identities` list
3. **Info-only low recurrence** — all events are INFO severity and fewer than 3 events

---

## Routing

### RouteRegistry (`tengen/routing/registry.py`)
A pure-function, first-match route registry. Routes are registered via the `@registry.register(queue_name)` decorator. Each route is a callable `(raw_event: dict) -> bool`. The first route whose matcher returns `True` wins.

All routes are auto-registered when `tengen.routing.routes` is imported (which happens in `router_main.py`).

### Route Matchers

| File | Queue | Match Condition |
|---|---|---|
| `cloud/aws/cloudtrail.py` | `runbook.cloudtrail` | `eventSource` ends with `.amazonaws.com` |
| `cloud/aws/guardduty.py` | `runbook.guardduty` | `detail-type == "GuardDuty Finding"` |
| `cloud/aws/eks.py` | `runbook.eks` | EKS cluster name present in request parameters |
| `cloud/gcp/event_audit.py` | `runbook.gcp.event_audit` | `"cloudaudit.googleapis.com"` in `logName` |
| `cloud/azure/activity.py` | `runbook.azure.activity` | `operationName.value` starts with `"Microsoft."` or `tenantId` present |
| `edr/crowdstrike.py` | `runbook.crowdstrike` | `event_type` is a CrowdStrike detection type |
| `k8s/audit.py` | `runbook.k8s` | `apiVersion` is `"audit.k8s.io/v1"` |
| `network/firewall.py` | `runbook.firewall` | `action` in `("DENY", "DROP", "BLOCK", "REJECT")` |

---

## n8n Connector

The n8n connector replaces the former per-source runbook agents, enricher pipeline, containment tools, and MCP servers with a single integration point. All playbook execution, enrichment, and containment logic now lives in n8n workflows, invoked via webhook dispatch.

### Architecture

The RouterAgent uses two ADK tools to dispatch events to n8n:

1. **`resolve_route(vendor, category, event_type)`** — Walks the hierarchical YAML routing spec to find the most specific matching webhook URL. Falls back through `_default` entries at each level. Raises `NoRouteError` if no match exists at any level.

2. **`execute_webhook(webhook_url, payload_json)`** — POSTs the event payload to the resolved n8n webhook URL and returns the JSON response. Handles retries and error classification.

### Route Resolver (`tengen/n8n/route_resolver.py`)

The `RouteResolver` loads a hierarchical YAML file and resolves `vendor → category → event_type` to a webhook URL.

- **Hierarchical lookup** — walks from most specific (vendor + category + event_type) to least specific (root `_default`)
- **`_default` fallback** — every level can define a `_default` entry that catches unmatched children
- **File watcher** — checks file mtime on every `resolve()` call and reloads if changed, enabling ConfigMap updates without pod restarts
- **`RouteMatch`** — frozen dataclass returned on success: `webhook_url`, `route_path`, `description`
- **`NoRouteError`** — raised when no route matches at any level, including root `_default`

### HTTP Client (`tengen/n8n/client.py`)

The `N8nClient` POSTs payloads to n8n webhook URLs with built-in resilience:

- **Retry with exponential backoff** — retries on 5xx, timeout, and connection errors up to `N8N_MAX_RETRIES` (default: 3)
- **Backoff formula** — `N8N_BACKOFF_BASE ^ attempt` seconds between retries (default base: 2 → waits 2s, 4s, 8s)
- **No retry on 4xx** — client errors are not transient and are routed directly to DLQ
- **DLQ on exhaustion** — after all retries fail, raises `N8nRequestFailed` so the orchestrator routes to the dead-letter queue
- **Configurable timeout** — per-request timeout via `N8N_TIMEOUT` (default: 30 seconds)

### Response Parser (`tengen/n8n/response_parser.py`)

`parse_response()` maps the freeform JSON returned by n8n workflows into an `EnrichedAlert`:

- Preserves the original `Alert` unchanged
- Stores the entire n8n response in the `enrichment` dict
- Extracts well-known fields (`severity`, `recommendations`, `iocs`, `verdict`) into `extracted` if present
- Sets `enrichment_error=True` on empty or `None` responses
- Records the `n8n_route_path` for traceability

### Error Handling

| n8n Response | Tengen Behavior |
|---|---|
| 2xx with valid JSON | Parse into EnrichedAlert, forward to Splunk |
| 5xx / timeout / connection error | Retry with exponential backoff up to max retries |
| Retries exhausted (5xx) | Route to DLQ, emit `n8n_dispatch_failed` metric |
| 4xx (client error) | No retry, route to DLQ immediately |
| 2xx with empty/malformed body | Set `enrichment_error=True` on EnrichedAlert, forward anyway |

### Deployment

The n8n routing spec is deployed as an OpenShift ConfigMap mounted into the pod filesystem:

```yaml
# ConfigMap mount
apiVersion: v1
kind: ConfigMap
metadata:
  name: tengen-n8n-routes
data:
  n8n_routes.yaml: |
    # ... routing spec contents ...
```

Set the `N8N_ROUTES_PATH` environment variable to the mount path (default: `/etc/tengen/n8n_routes.yaml`). The `RouteResolver` watches the file for changes, so ConfigMap updates propagate without pod restarts.

---

## n8n Routing Spec

The routing spec is a hierarchical YAML file that maps `vendor → category → event_type` to n8n webhook URLs. Every level supports a `_default` fallback for unmatched events.

### Example

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

### Resolution Order

For a request `resolve_route("aws", "cloudtrail", "root_login")`:

1. Check `routes.aws.cloudtrail.root_login` — if it has a `webhook`, return it
2. Check `routes.aws.cloudtrail._default` — category-level fallback
3. Check `routes.aws._default` — vendor-level fallback
4. Check `routes._default` — root-level catch-all
5. Raise `NoRouteError` if none matched

---

## Query Agent

The `QueryAgent` (`tengen/agents/query.py`) is a standalone analyst-facing LLM agent for ad-hoc security investigation. It does not participate in the automated pipeline — it's invoked directly by security analysts.

### Example Queries
- *"Show me all IAM API calls from 203.0.113.5 in the last 24 hours"*
- *"Find CrowdStrike CRITICAL detections this week involving credential dumping"*
- *"What Azure operations did admin@contoso.com perform yesterday?"*
- *"Correlate IP 1.2.3.4 across CloudTrail, CrowdStrike, and Azure — is it in all three?"*
- *"List all Kubernetes exec operations in the production namespace this month"*

### Cross-Source Correlation
`correlate_ip_across_sources(ip_address, start_time, end_time)` queries CloudTrail by source IP and cross-references with IP reputation and geolocation, returning a unified summary.

---

## Forwarder

### SplunkHECClient (`tengen/forwarder/splunk_client.py`)
Batched, retrying Splunk HEC forwarder with exponential backoff.
- Configurable batch size (`SPLUNK_BATCH_SIZE`, default: 25 events)
- Retries up to 5 times with backoff on transient failures
- Each event is wrapped in `{"time": ..., "source": "tengen", "sourcetype": "tengen:finding", "event": ...}`

### EnrichedAlertForwarder (`tengen/forwarder/enriched_forwarder.py`)
Drains the `[enriched]` queue and forwards to Splunk HEC. Uses `sourcetype: tengen:finding`.

### DLQForwarder (`tengen/forwarder/dlq_forwarder.py`)
Drains the `[alerts.dlq]` queue and forwards to Splunk HEC. Uses `sourcetype: tengen:dlq` for easy filtering. Dead-letter events are never dropped — they are always forwarded for analyst review.

---

## Dashboard

The Tengen dashboard is a FastAPI application (`tengen/dashboard/app.py`) that provides real-time visibility into the pipeline.

### Starting the Dashboard
```bash
tengen-dashboard
# → http://localhost:8080
```

### API Endpoints

| Endpoint | Description |
|---|---|
| `GET /api/overview` | High-level pipeline summary: event counts, error rates, top routes |
| `GET /api/queues` | Live RabbitMQ queue depths via the Management API |
| `GET /api/metrics` | Aggregated metrics from MetricsStore (SQLite) |
| `GET /api/routes` | All registered routes from RouteRegistry |
| `GET /api/agents` | LLM agent activity from metrics (which agents ran, error counts) |

### Dashboard UI (`tengen/dashboard/static/index.html`)
Dark-themed single-page application. Polls all `/api/*` endpoints every 10 seconds. Displays:
- Queue depth chart for all RabbitMQ queues
- Route match counts (which routes are getting the most traffic)
- n8n dispatch success/failure rates
- Normalization source breakdown
- DLQ depth (highlighted in red when non-zero)

---

## Metrics

### MetricsEmitter (`tengen/metrics/emitter.py`)
Fire-and-forget metric publisher. Never raises exceptions. Emits structured JSON events to the `[tengen.metrics]` RabbitMQ queue. Used throughout the pipeline:

| Event | Phase | Data |
|---|---|---|
| `alert_ingested` | Consumer | `{source, queue}` |
| `event_normalized` | Normalization | `{source_type}` |
| `normalization_error` | Normalization | `{error, source_type}` |
| `event_suppressed` | Triage | `{reason, score}` |
| `incident_created` | Triage | `{score, source_type}` |
| `incident_updated` | Triage | `{incident_id, event_count}` |
| `route_matched` | Routing | `{route, queue}` |
| `dlq_enqueued` | Routing | `{reason}` |
| `n8n_dispatch_success` | n8n | `{route_path, duration_ms}` |
| `n8n_dispatch_failed` | n8n | `{route_path, error, attempts}` |
| `forwarding_success` | Forwarder | `{destination, count}` |
| `forwarding_failure` | Forwarder | `{destination, error}` |

### MetricsStore (`tengen/dashboard/metrics_store.py`)
Thread-safe SQLite-backed counter and timing store. Flushes in-memory accumulation to SQLite every 60 seconds. Exposes bucketed counters to the dashboard API.

---

## Configuration

Copy `.env.example` to `.env` and fill in the values for the integrations you use. All settings are loaded via `tengen/config.py` (a dataclass reading from environment variables).

### Required

| Variable | Description |
|---|---|
| `GOOGLE_API_KEY` | Gemini API key for all LLM agents |
| `RABBITMQ_URL` | RabbitMQ connection URL (e.g. `amqp://guest:guest@localhost:5672/`) |

### n8n

| Variable | Default | Description |
|---|---|---|
| `N8N_ROUTES_PATH` | `/etc/tengen/n8n_routes.yaml` | Path to the n8n routing spec YAML file |
| `N8N_TIMEOUT` | `30` | HTTP request timeout in seconds for n8n webhook calls |
| `N8N_MAX_RETRIES` | `3` | Maximum retry attempts on 5xx / timeout / connection errors |
| `N8N_BACKOFF_BASE` | `2` | Base for exponential backoff between retries (seconds) |

### AWS

| Variable | Default | Description |
|---|---|---|
| `AWS_REGION` | `us-east-1` | AWS region for boto3 clients |
| `AWS_ENDPOINT_URL` | — | Override for LocalStack (`http://localhost:4566`) |
| `SQS_QUEUE_URL` | — | SQS queue URL for SqsConsumer |

### GCP

| Variable | Description |
|---|---|
| `GCP_PROJECT_ID` | GCP project ID for Audit Log queries |
| `PUBSUB_PROJECT_ID` | GCP project ID for Pub/Sub consumer |
| `PUBSUB_SUBSCRIPTION_ID` | Pub/Sub subscription name |
| `PUBSUB_EMULATOR_HOST` | Pub/Sub emulator address for local dev (e.g. `localhost:8085`) |

### Azure

| Variable | Description |
|---|---|
| `AZURE_TENANT_ID` | Azure AD tenant ID |
| `AZURE_CLIENT_ID` | Service principal / app registration client ID |
| `AZURE_CLIENT_SECRET` | Service principal client secret |
| `AZURE_SUBSCRIPTION_ID` | Azure subscription ID for Activity Log queries |

### CrowdStrike

| Variable | Default | Description |
|---|---|---|
| `CROWDSTRIKE_CLIENT_ID` | — | Falcon API client ID |
| `CROWDSTRIKE_CLIENT_SECRET` | — | Falcon API client secret |
| `CROWDSTRIKE_BASE_URL` | `https://api.crowdstrike.com` | Falcon API base URL |

### Kubernetes

| Variable | Description |
|---|---|
| `K8S_KUBECONFIG` | Path to kubeconfig file. Leave empty for in-cluster config or `~/.kube/config` |

### Kafka

| Variable | Default | Description |
|---|---|---|
| `KAFKA_BOOTSTRAP_SERVERS` | — | Comma-separated broker list |
| `KAFKA_GROUP_ID` | `tengen` | Consumer group ID |
| `KAFKA_TOPICS` | `security-events` | Comma-separated topic list |

### Splunk HEC

| Variable | Default | Description |
|---|---|---|
| `SPLUNK_HEC_URL` | — | Splunk HEC endpoint (e.g. `https://splunk:8088`) |
| `SPLUNK_HEC_TOKEN` | — | Splunk HEC token |
| `SPLUNK_INDEX` | `tengen` | Target Splunk index |
| `SPLUNK_BATCH_SIZE` | `25` | Events per HEC batch request |

### Splunk ES (consumer)

| Variable | Default | Description |
|---|---|---|
| `SPLUNK_ES_HOST` | — | Splunk ES hostname |
| `SPLUNK_ES_PORT` | `8089` | Splunk management port |
| `SPLUNK_ES_TOKEN` | — | Splunk API token |
| `SPLUNK_ES_SEARCH` | `| search index=notable` | SPL search for notable events |

### Dashboard

| Variable | Default | Description |
|---|---|---|
| `DASHBOARD_HOST` | `0.0.0.0` | Dashboard bind host |
| `DASHBOARD_PORT` | `8080` | Dashboard bind port |
| `RABBITMQ_MGMT_URL` | `http://localhost:15672` | RabbitMQ Management API URL |
| `RABBITMQ_USER` | `guest` | RabbitMQ management username |
| `RABBITMQ_PASS` | `guest` | RabbitMQ management password |

### Universal HTTP Consumer

| Variable | Default | Description |
|---|---|---|
| `UNIVERSAL_HTTP_HOST` | `0.0.0.0` | Ingest endpoint bind host |
| `UNIVERSAL_HTTP_PORT` | `8088` | Ingest endpoint bind port |
| `UNIVERSAL_HTTP_TOKEN` | — | Bearer token for ingest authentication (optional) |

### PagerDuty

| Variable | Description |
|---|---|
| `PAGERDUTY_API_KEY` | PagerDuty Events v2 API key |

### LLM

| Variable | Default | Description |
|---|---|---|
| `MODEL_NAME` | `gemini-2.0-flash` | Gemini model for all LLM agents |

---

## Quick Start

### Prerequisites
- Python 3.11+
- Docker + Docker Compose (for local stack)
- A Google API key (Gemini)

### Installation

```bash
git clone https://github.com/mrcoggsworth/Tengen.git
cd Tengen
pip install -e ".[dev]"
cp .env.example .env
# Edit .env — at minimum set GOOGLE_API_KEY and RABBITMQ_URL
```

### Start the local infrastructure

```bash
docker compose -f docker/docker-compose.yml up -d rabbitmq localstack
```

### Run the full pipeline

```bash
# Terminal 1: Event router
tengen-router

# Terminal 2: Enriched-alert + DLQ forwarder
tengen-forwarder

# Terminal 3: Dashboard → http://localhost:8080
tengen-dashboard

# Terminal 4: Universal HTTP ingest endpoint
tengen-ingest
```

### Process an event programmatically

```python
import asyncio, json
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from tengen.agents.orchestrator import orchestrator_agent

runner = Runner(
    agent=orchestrator_agent,
    app_name="tengen",
    session_service=InMemorySessionService(),
)

# Any raw event — CloudTrail, GCP Audit, Azure, CrowdStrike, K8s, firewall, DDoS
raw_event = {
    "eventVersion": "1.08",
    "eventSource": "iam.amazonaws.com",
    "eventName": "CreateAccessKey",
    "eventTime": "2024-01-15T10:30:00Z",
    "sourceIPAddress": "203.0.113.5",
    "userIdentity": {"type": "IAMUser", "userName": "alice", "arn": "arn:aws:iam::123456789:user/alice"},
}

asyncio.run(runner.run_async(
    user_id="analyst",
    session_id="s1",
    new_message={"role": "user", "parts": [{"text": json.dumps(raw_event)}]},
))
```

### Send an event via HTTP ingest

```bash
curl -X POST http://localhost:8088/ingest \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-ingest-token" \
  -d '{"eventSource": "iam.amazonaws.com", "eventName": "DeleteUser", ...}'
```

### Run an ad-hoc analyst query

```python
import asyncio
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from tengen.agents.query import query_agent

runner = Runner(agent=query_agent, app_name="tengen", session_service=InMemorySessionService())

asyncio.run(runner.run_async(
    user_id="analyst",
    session_id="q1",
    new_message={"role": "user", "parts": [{"text": "Find all CloudTrail events from 203.0.113.5 in the last 24 hours"}]},
))
```

---

## Docker Compose

`docker/docker-compose.yml` defines the full local development stack:

| Service | Port | Purpose |
|---|---|---|
| `rabbitmq` | 5672, 15672 | RabbitMQ broker + Management UI |
| `zookeeper` | 2181 | Kafka dependency |
| `kafka` | 9092 | Kafka broker |
| `localstack` | 4566 | AWS services emulator (SQS, S3, IAM, CloudTrail, GuardDuty, EC2) |
| `pubsub-emulator` | 8085 | GCP Pub/Sub emulator |
| `router` | — | Tengen router pod |
| `forwarder` | — | Tengen enriched + DLQ forwarder |
| `dashboard` | 8080 | Tengen observability dashboard |
| `ingest` | 8088 | Universal HTTP ingest endpoint |

```bash
# Start everything
docker compose -f docker/docker-compose.yml up -d

# Start only infrastructure (no Tengen pods)
docker compose -f docker/docker-compose.yml up -d rabbitmq localstack pubsub-emulator

# View logs
docker compose -f docker/docker-compose.yml logs -f router
```

---

## Entry Points

| Command | Module | Description |
|---|---|---|
| `tengen-router` | `tengen.router_main` | Starts the RabbitMQ-backed routing pipeline |
| `tengen-forwarder` | `tengen.forwarder_main` | Starts enriched-alert + DLQ forwarding threads |
| `tengen-dashboard` | `tengen.dashboard_main` | Starts the FastAPI observability dashboard |
| `tengen-ingest` | `tengen.consumers.universal_consumer` | Starts the Universal HTTP ingest endpoint |

---

## Running Tests

```bash
# All tests
pytest

# By category
pytest tests/test_route_resolver.py     # n8n route resolver (9 tests)
pytest tests/test_n8n_client.py         # n8n HTTP client (7 tests)
pytest tests/test_response_parser.py    # n8n response parser (6 tests)
pytest tests/test_enriched_alert.py     # EnrichedAlert model (4 tests)
pytest tests/test_router_n8n.py         # Router agent n8n integration (6 tests)
pytest tests/test_normalizers.py        # Source detection + all 7 normalizers
pytest tests/test_triage.py             # Correlation, scoring, suppression
pytest tests/test_models.py             # Pydantic model validation
pytest tests/test_forwarder.py          # Forwarder tests
pytest tests/test_tools.py             # Alert parser
pytest tests/test_udm_model.py          # UDM model tests
pytest tests/test_udm_parser.py         # UDM parser tests
pytest tests/test_field_registry.py     # Field registry tests
pytest tests/test_model_updater.py      # Model updater tests
pytest tests/test_dashboard_udm.py      # Dashboard UDM endpoint tests

# With coverage
pytest --cov=tengen --cov-report=term-missing
```

All tests are fully offline — cloud SDK calls are mocked. No external services required to run the test suite.

---

## Extending Tengen

### Adding a new log source

1. **Create a normalizer** in `tengen/tools/normalizers/<source>_normalizer.py` implementing `normalize(raw: dict) -> NormalizedEvent`
2. **Add detection heuristics** to `detect_source_type()` in `tengen/tools/normalizers/registry.py`
3. **Register the normalizer** in the `normalize()` dispatch in the same file
4. **Add a route matcher** in `tengen/routing/routes/<category>/<source>.py` using `@registry.register(QUEUE_NAME)`
5. **Import the route** in `tengen/routing/routes/__init__.py` so it auto-registers
6. **Add a queue constant** to `tengen/queue/queues.py`
7. **Add a route entry** in `n8n_routes.yaml` pointing to your n8n workflow webhook
8. **Create the n8n workflow** in your n8n instance to handle events for this source
9. **Add tests** in `tests/test_normalizers.py`

### Adding a new n8n workflow

1. **Design the workflow** in n8n — it will receive the full event payload as a JSON POST body and must return a JSON response
2. **Add a route entry** to your `n8n_routes.yaml` at the appropriate level:
   ```yaml
   routes:
     <vendor>:
       <category>:
         <event_type>:
           webhook: https://your-n8n.example.com/webhook/<your-workflow-id>
           description: "What this workflow handles"
   ```
3. **Use `_default` entries** for catch-all handling — if your workflow handles all events for a vendor or category, place it at that level
4. **Return structured JSON** from the workflow — the response parser extracts well-known fields (`severity`, `recommendations`, `iocs`, `verdict`) automatically
5. **Reload without restart** — update the ConfigMap; the RouteResolver detects file changes on the next request

# Tengen — Agentic Security Harness

Tengen is a production-grade, multi-cloud security agentic harness built on [Google ADK](https://google.github.io/adk-docs/). It ingests security events from any cloud provider or EDR platform, normalizes them into a universal schema, triages and correlates them into incidents, executes real containment actions against live cloud APIs, enriches findings with external threat intelligence, and forwards results to your SIEM — all driven by LLM agents coordinated through a durable RabbitMQ event backbone.

Tengen is the spiritual successor to [LogPose](https://github.com/mrcoggsworth/LogPose), combining LogPose's production infrastructure (durable queuing, consumer pods, enricher pipeline, dashboard, forwarder) with an LLM agentic layer for reasoning, runbook execution, and decision-making.

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
- [Runbooks](#runbooks)
- [Enricher Pipeline](#enricher-pipeline)
- [Containment](#containment)
- [External Enrichment](#external-enrichment)
- [MCP Servers](#mcp-servers)
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
│  PHASE 4 — ROUTING  (RouterAgent + RouteRegistry)                         │
│                                                                           │
│  Pure-function first-match routing (deterministic, no LLM for routing)   │
│  aws.cloudtrail   → [runbook.cloudtrail]                                 │
│  aws.guardduty    → [runbook.guardduty]                                  │
│  aws.eks          → [runbook.eks]                                        │
│  gcp.audit        → [runbook.gcp.event_audit]                            │
│  azure.activity   → [runbook.azure.activity]                             │
│  edr.crowdstrike  → [runbook.crowdstrike]                                │
│  k8s.audit        → [runbook.k8s]                                        │
│  network.firewall → [runbook.firewall]                                   │
│  unmatched        → [alerts.dlq]                                         │
└──────────────────────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────────────────┐
│  PHASE 5 — RUNBOOKS  (per-source LlmAgents + EnricherPipeline)           │
│                                                                           │
│  Each runbook pod:                                                        │
│    1. EnricherPipeline (staged async, per-enricher timeout, TTL cache)   │
│    2. LlmAgent reasoning over extracted fields                            │
│    3. Loads and executes best-match YAML runbook                         │
│    4. Produces Finding JSON (enriched, with remediation steps)           │
│                         ↓                                                 │
│                 RabbitMQ [enriched] queue                                 │
└──────────────────────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────────────────┐
│  PHASE 6 — CONTAINMENT  (ContainmentAgent)                                │
│                                                                           │
│  CRITICAL / HIGH  → auto-execute containment tools immediately           │
│  MEDIUM           → return pending_analyst_approval JSON                 │
│  LOW / INFO       → skip                                                 │
│                                                                           │
│  AWS: disable_iam_access_key · revoke_sts_sessions                       │
│       modify_security_group_deny · disable_iam_user                      │
│  GCP: disable_service_account · add_vpc_firewall_deny                    │
│  Azure: disable_azure_ad_user · revoke_azure_refresh_tokens              │
│  K8s: cordon_node · delete_pod · delete_sa_token · network_policy_deny   │
└──────────────────────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────────────────┐
│  PHASE 7 — EXTERNAL ENRICHMENT  (EnrichmentAgent)                        │
│                                                                           │
│  IP reputation → AbuseIPDB / VirusTotal                                  │
│  IP geolocation → ipinfo.io                                              │
│  Domain info    → SecurityTrails                                         │
│  File hash      → VirusTotal                                             │
│  User context   → Okta / Azure Graph                                     │
│  Asset context  → CMDB / AWS Config                                      │
└──────────────────────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────────────────────┐
│  PHASE 8 — FORWARDING                                                     │
│                                                                           │
│  EnrichedAlertForwarder → Splunk HEC (batched, retrying, exp. backoff)   │
│  DLQForwarder           → Splunk HEC (sourcetype: tengen:dlq)            │
│  ForwarderAgent         → PagerDuty Events v2 (HIGH/CRITICAL only)       │
└──────────────────────────────────────────────────────────────────────────┘

QueryAgent ──────── ad-hoc analyst NL queries across all sources ──────────
                    CloudTrail · GCP · Azure · CrowdStrike · K8s
                    Cross-source IP correlation

Dashboard ──────── FastAPI + browser UI  http://localhost:8080 ────────────
                   Live queue depths · route counts · runbook stats
                   containment counts · normalization rates · DLQ depth

MetricsEmitter ─── fire-and-forget throughout every phase ─────────────────
                   → [tengen.metrics] → MetricsStore (SQLite) → Dashboard
```

---

## Agent Pipeline

### OrchestratorAgent (`tengen/agents/orchestrator.py`)
The top-level coordinator. Drives the complete 6-step pipeline for every event: normalize → triage → route → contain → enrich → forward. Instruments each phase with `MetricsEmitter`. If any step fails, it records the failure and continues where possible rather than dropping the event.

**Tools:** `normalize_event`, `validate_normalized_event`, `emit_metric`, `legacy_parse_alert`
**Sub-agents:** NormalizerAgent, TriageAgent, RouterAgent, ContainmentAgent, EnrichmentAgent, ForwarderAgent

### NormalizerAgent (`tengen/agents/normalizer.py`)
Detects the log source type and normalizes raw events into the universal `NormalizedEvent` schema. Supports all 8 source types. Returns the NormalizedEvent JSON or an error JSON if normalization fails.

**Tools:** `detect_source_type`, `detect_and_normalize`

### TriageAgent (`tengen/agents/triage.py`)
Receives a NormalizedEvent and an in-memory incident store. Correlates the event into an existing open Incident (same actor + same source type within a 15-minute window) or creates a new one. Computes a priority score. Checks suppression rules. Returns a structured result indicating whether the incident should proceed or be suppressed.

**Tools:** `correlate_event`, `score_incident`, `check_suppression`, `update_incident_score`

### RouterAgent (`tengen/agents/router.py`)
Detects the source type and transfers to the correct runbook agent. Uses the `RouteRegistry` for deterministic first-match routing. Falls back to source-type mapping if the raw event cannot be matched by the registry.

**Tools:** `detect_source_type`, `route_to_queue`
**Sub-agents:** CloudTrailRunbookAgent, GCPAuditRunbookAgent, AzureRunbookAgent, EDRRunbookAgent, K8sRunbookAgent

### CloudTrailRunbookAgent (`tengen/agents/cloudtrail_runbook.py`)
Investigates AWS CloudTrail events. Enriches with caller identity, source IP, error context. Loads and executes the best-match AWS runbook YAML. Produces a structured Finding.

**Tools:** `list_aws_runbooks`, `load_aws_runbook`, `enrich_cloudtrail_event`

### GCPAuditRunbookAgent (`tengen/agents/gcp_audit_runbook.py`)
Investigates GCP Audit Log events. Enriches with principal email, service name, resource name, authorization info. Produces a structured Finding.

**Tools:** `list_gcp_runbooks`, `load_gcp_runbook`, `enrich_gcp_audit_event`

### AzureRunbookAgent (`tengen/agents/azure_runbook.py`)
Investigates Azure Activity Log events. Extracts caller, operation name, resource, subscription, correlation ID, and source IP. Checks for privilege escalation patterns (role assignments, service principal credential updates). Produces a structured Finding.

**Tools:** `list_azure_runbooks`, `load_azure_runbook`, `enrich_azure_event`, `check_azure_privilege_escalation`

### EDRRunbookAgent (`tengen/agents/edr_runbook.py`)
Investigates CrowdStrike detections. Extracts MITRE ATT&CK tactics and techniques, file hashes, command lines, device hostname. Classifies into malware_detection, lateral_movement, or credential_dumping. Produces a structured Finding.

**Tools:** `list_edr_runbooks`, `load_edr_runbook`, `enrich_crowdstrike_event`, `classify_threat_type`

### K8sRunbookAgent (`tengen/agents/k8s_runbook.py`)
Investigates Kubernetes API server audit events. Extracts user, verb, resource, namespace, source IP, user-agent. Classifies into privileged_container, secrets_access, or anomalous_exec. Produces a structured Finding.

**Tools:** `list_k8s_runbooks`, `load_k8s_runbook`, `enrich_k8s_event`, `classify_k8s_threat`

### ContainmentAgent (`tengen/agents/containment.py`)
Executes real containment actions against live cloud APIs based on Finding severity. CRITICAL/HIGH severities trigger immediate automated execution. MEDIUM returns a pending approval response for analyst review. LOW/INFO are skipped.

**Tools (12 total):**
- AWS: `disable_iam_access_key`, `revoke_sts_sessions`, `modify_security_group_deny`, `disable_iam_user`
- GCP: `disable_gcp_service_account`, `add_gcp_firewall_deny`
- Azure: `disable_azure_ad_user`, `revoke_azure_refresh_tokens`
- K8s: `cordon_k8s_node`, `delete_k8s_pod`, `delete_k8s_service_account_token`, `create_k8s_network_policy_deny`

### EnrichmentAgent (`tengen/agents/enrichment_agent.py`)
Examines Finding enrichment fields for available indicators and performs targeted external lookups. Merges all results back into the Finding's enrichment dict. Failed individual lookups are recorded in `enrichment.lookup_errors` rather than stopping the pipeline.

**Tools:** `lookup_ip_reputation`, `lookup_ip_geo`, `lookup_domain`, `lookup_file_hash`, `lookup_user_context`, `lookup_asset_context`

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
│
├── docker/
│   └── docker-compose.yml              # RabbitMQ, Kafka, LocalStack, Pub/Sub emulator
│
├── runbooks/                           # YAML runbook definitions (no code changes needed to add)
│   ├── aws/
│   │   ├── root_account_usage.yaml
│   │   └── unauthorized_api_call.yaml
│   ├── gcp/
│   │   ├── admin_activity.yaml
│   │   └── data_access.yaml
│   ├── azure/
│   │   ├── unauthorized_access.yaml
│   │   ├── privilege_escalation.yaml
│   │   └── suspicious_signin.yaml
│   ├── edr/
│   │   ├── malware_detection.yaml
│   │   ├── lateral_movement.yaml
│   │   └── credential_dumping.yaml
│   ├── k8s/
│   │   ├── privileged_container.yaml
│   │   ├── secrets_access.yaml
│   │   └── anomalous_exec.yaml
│   └── network/
│       ├── firewall_block_surge.yaml
│       └── ddos_inbound.yaml
│
├── tengen/
│   ├── config.py                       # All settings (dataclass, reads from env)
│   ├── router_main.py                  # Entry point: start the routing pipeline
│   ├── forwarder_main.py               # Entry point: start enriched + DLQ forwarders
│   ├── dashboard_main.py               # Entry point: start the FastAPI dashboard
│   │
│   ├── agents/                         # All LlmAgent definitions
│   │   ├── orchestrator.py             # Top-level 6-step pipeline coordinator
│   │   ├── normalizer.py               # NormalizerAgent
│   │   ├── triage.py                   # TriageAgent
│   │   ├── router.py                   # RouterAgent (5 runbook sub-agents)
│   │   ├── cloudtrail_runbook.py       # AWS CloudTrail investigation
│   │   ├── gcp_audit_runbook.py        # GCP Audit Log investigation
│   │   ├── azure_runbook.py            # Azure Activity Log investigation
│   │   ├── edr_runbook.py              # CrowdStrike EDR investigation
│   │   ├── k8s_runbook.py              # Kubernetes audit investigation
│   │   ├── containment.py              # ContainmentAgent (12 tools)
│   │   ├── enrichment_agent.py         # EnrichmentAgent (6 external lookups)
│   │   ├── query.py                    # QueryAgent (analyst-facing NL queries)
│   │   └── forwarder.py                # ForwarderAgent (Splunk + PagerDuty)
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
│   │   │                               #   TargetContext, NetworkContext, Outcome
│   │   ├── incident.py                 # Incident, IncidentStatus
│   │   ├── finding.py                  # Finding, RemediationStep
│   │   ├── enriched_alert.py           # EnrichedAlert (runbook output)
│   │   └── runbook.py                  # Runbook, RunbookStep
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
│   ├── enrichers/                      # EnricherPipeline (staged async)
│   │   ├── protocol.py                 # Enricher Protocol (structural subtyping)
│   │   ├── context.py                  # EnricherContext dataclass + Principal
│   │   ├── cache.py                    # PrincipalCache ABC + InProcessTTLCache (LRU+TTL)
│   │   ├── runner.py                   # EnricherPipeline (ThreadPoolExecutor, budgets)
│   │   └── cloud/aws/cloudtrail/       # CloudTrail-specific enrichers
│   │       ├── schema.py               # CloudTrailEnrichment frozen model
│   │       ├── principal_identity.py   # Stage 0: extract Principal from userIdentity
│   │       ├── principal_history.py    # Stage 1: CloudTrail lookup_events (last 24h)
│   │       ├── write_filter.py         # Stage 1: filter to successful write calls
│   │       └── object_inspection.py    # Stage 2: inspect S3/IAM resources
│   │
│   ├── runbooks/                       # BaseRunbook + runbook pod implementations
│   │   ├── base.py                     # BaseRunbook ABC
│   │   ├── cloud/aws/cloudtrail.py     # CloudTrailRunbook
│   │   ├── cloud/gcp/event_audit.py    # GcpEventAuditRunbook
│   │   ├── cloud/azure/activity.py     # AzureActivityRunbook
│   │   ├── edr/crowdstrike.py          # CrowdStrikeRunbook
│   │   └── k8s/audit.py               # K8sAuditRunbook
│   │
│   ├── tools/                          # Pure-Python tool functions
│   │   ├── alert_parser.py             # parse_cloudtrail_event, parse_gcp_audit_event
│   │   ├── enrichment.py               # Field extraction + 6 external lookups
│   │   ├── triage_tools.py             # correlate_event, score_incident, check_suppression
│   │   ├── runbook_loader.py           # list_runbooks, load_runbook (YAML loader)
│   │   ├── forwarder_tools.py          # forward_to_siem, forward_to_pagerduty
│   │   ├── normalizers/
│   │   │   ├── registry.py             # detect_source_type() + normalize() dispatch
│   │   │   ├── aws_normalizer.py       # CloudTrail → NormalizedEvent
│   │   │   ├── gcp_normalizer.py       # GCP Audit → NormalizedEvent
│   │   │   ├── azure_normalizer.py     # Azure Activity → NormalizedEvent
│   │   │   ├── crowdstrike_normalizer.py  # CS Detection → NormalizedEvent
│   │   │   ├── firewall_normalizer.py  # Firewall deny → NormalizedEvent
│   │   │   ├── ddos_normalizer.py      # DDoS flow → NormalizedEvent
│   │   │   └── k8s_normalizer.py       # K8s audit → NormalizedEvent (OpenShift aware)
│   │   └── containment/
│   │       ├── aws_containment.py      # boto3 IAM + EC2 containment
│   │       ├── gcp_containment.py      # Google IAM + Compute containment
│   │       ├── azure_containment.py    # Microsoft Graph containment
│   │       └── k8s_containment.py      # Kubernetes API containment
│   │
│   ├── mcp_servers/                    # MCP stdio servers for data retrieval
│   │   ├── cloudtrail_server.py
│   │   ├── gcp_audit_server.py
│   │   ├── azure_activity_server.py
│   │   ├── crowdstrike_server.py
│   │   └── k8s_audit_server.py
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
    ├── test_normalizers.py             # 9 tests: source detection + all 7 normalizers
    ├── test_triage.py                  # 14 tests: correlate, score, suppress
    ├── test_containment.py             # 11 tests: all cloud containment tools (mocked)
    ├── test_enrichment.py              # 8 tests: external lookups (mocked HTTP)
    ├── test_cloudtrail_runbook.py      # CloudTrail runbook agent tests
    ├── test_gcp_audit_runbook.py       # GCP runbook agent tests
    ├── test_models.py                  # Pydantic model validation tests
    ├── test_orchestrator.py            # Orchestrator pipeline tests
    ├── test_router.py                  # Router agent tests
    ├── test_forwarder.py               # Forwarder tests
    └── test_tools.py                   # Alert parser + enrichment field extraction
```

---

## Supported Log Sources

| Source | Normalizer | Route Matcher | Runbook Agent | MCP Server | YAML Runbooks |
|---|---|---|---|---|---|
| AWS CloudTrail | `aws_normalizer.py` | `routes/cloud/aws/cloudtrail.py` | `cloudtrail_runbook_agent` | `cloudtrail_server.py` | root_account_usage, unauthorized_api_call |
| AWS GuardDuty | `aws_normalizer.py` | `routes/cloud/aws/guardduty.py` | `cloudtrail_runbook_agent` | `cloudtrail_server.py` | — |
| AWS EKS | `aws_normalizer.py` | `routes/cloud/aws/eks.py` | `cloudtrail_runbook_agent` | `cloudtrail_server.py` | — |
| GCP Audit Log | `gcp_normalizer.py` | `routes/cloud/gcp/event_audit.py` | `gcp_audit_runbook_agent` | `gcp_audit_server.py` | admin_activity, data_access |
| Azure Activity | `azure_normalizer.py` | `routes/cloud/azure/activity.py` | `azure_runbook_agent` | `azure_activity_server.py` | unauthorized_access, privilege_escalation, suspicious_signin |
| CrowdStrike EDR | `crowdstrike_normalizer.py` | `routes/edr/crowdstrike.py` | `edr_runbook_agent` | `crowdstrike_server.py` | malware_detection, lateral_movement, credential_dumping |
| Kubernetes Audit | `k8s_normalizer.py` | `routes/k8s/audit.py` | `k8s_runbook_agent` | `k8s_audit_server.py` | privileged_container, secrets_access, anomalous_exec |
| OpenShift Audit | `k8s_normalizer.py` | `routes/k8s/audit.py` | `k8s_runbook_agent` | `k8s_audit_server.py` | (inherits K8s runbooks) |
| Firewall Deny | `firewall_normalizer.py` | `routes/network/firewall.py` | — | — | firewall_block_surge |
| DDoS Flow | `ddos_normalizer.py` | `routes/network/firewall.py` | — | — | ddos_inbound |

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
| `raw_event` | `dict` | Original raw event (preserved for runbook access) |
| `tags` | `list[str]` | Classification tags (tactic, technique, provider) |
| `labels` | `dict[str, str]` | Key-value metadata for filtering |

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
| `findings` | `list[Finding]` | Findings produced by runbook agents |
| `status` | `IncidentStatus` | `open`, `triaging`, `contained`, `closed`, `suppressed` |
| `priority_score` | `float` | Computed priority score |
| `suppressed` | `bool` | Whether this incident has been suppressed |
| `suppression_reason` | `str` | Why it was suppressed |
| `created_at` | `str` | ISO 8601 creation time |
| `updated_at` | `str` | ISO 8601 last update time |
| `labels` | `dict[str, str]` | Metadata labels |

### `Finding` (`tengen/models/finding.py`)
The output of a runbook agent. Contains the full investigative result and remediation guidance.

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
| `runbook.cloudtrail` | AWS CloudTrail events |
| `runbook.guardduty` | AWS GuardDuty findings |
| `runbook.eks` | AWS EKS events |
| `runbook.gcp.event_audit` | GCP Audit Log events |
| `runbook.azure.activity` | Azure Activity Log events |
| `runbook.crowdstrike` | CrowdStrike EDR detections |
| `runbook.k8s` | Kubernetes audit events |
| `runbook.firewall` | Firewall / DDoS events |
| `enriched` | Enriched Findings ready for forwarding |
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

## Runbooks

### YAML Runbook Format
Each YAML runbook defines investigation steps as structured data. No code changes are required to add a new runbook — just create a new YAML file in the appropriate `runbooks/<provider>/` directory.

```yaml
name: example_runbook
description: >
  What this runbook investigates.
steps:
  - id: step_name
    description: What to do in this step.
    actions:
      - Extract: specific fields from the event
      - Check: condition against extracted data
      - Query: data source for correlated activity
    severity_matrix:
      CRITICAL: conditions that warrant CRITICAL
      HIGH: conditions that warrant HIGH
  - id: containment
    description: Containment actions to take.
    actions:
      - If severity in [CRITICAL, HIGH]: containment_action(parameters)
  - id: produce_finding
    description: Output the structured Finding.
    output_fields:
      - finding_id
      - source
      - severity
      - title
      - description
      - enrichment
      - remediation_steps
```

### Available Runbooks

**AWS (`runbooks/aws/`)**
- `root_account_usage.yaml` — AWS root account API activity
- `unauthorized_api_call.yaml` — AccessDenied / UnauthorizedOperation errors

**GCP (`runbooks/gcp/`)**
- `admin_activity.yaml` — GCP admin write operations
- `data_access.yaml` — GCP data read operations

**Azure (`runbooks/azure/`)**
- `unauthorized_access.yaml` — Failed logins, unexpected API calls, anomalous access patterns
- `privilege_escalation.yaml` — Role assignments, service principal credential updates, AAD directory changes
- `suspicious_signin.yaml` — Impossible travel, anonymous proxy, credential spray, MFA bypass

**EDR (`runbooks/edr/`)**
- `malware_detection.yaml` — File-based malware, ransomware, droppers; SHA256 enrichment, scope assessment
- `lateral_movement.yaml` — Pass-the-hash, WMI, PsExec, SMB, RDP; movement path reconstruction
- `credential_dumping.yaml` — LSASS, SAM, NTDS.dit, DCSync; domain-wide impact assessment

**Kubernetes (`runbooks/k8s/`)**
- `privileged_container.yaml` — Privileged pod creation; host breakout risk assessment
- `secrets_access.yaml` — Anomalous secret reads; baseline comparison, exfiltration detection
- `anomalous_exec.yaml` — kubectl exec/attach; command analysis, SA token exposure assessment

**Network (`runbooks/network/`)**
- `firewall_block_surge.yaml` — Port scan, brute-force; IP reputation enrichment, geo-blocking
- `ddos_inbound.yaml` — Volumetric, protocol, application-layer attacks; mitigation strategy selection

---

## Enricher Pipeline

The `EnricherPipeline` (`tengen/enrichers/runner.py`) runs cloud-specific enrichers in stages with a total budget timeout (default: 8 seconds).

### Execution Model
- **Stage 0 enrichers** run first and sequentially (they extract foundation data like principal identity)
- **Stage 1+ enrichers** run in parallel within each stage using `ThreadPoolExecutor`
- Each enricher has an individual timeout (default: 3 seconds per enricher)
- A total budget timeout caps the entire pipeline (default: 8 seconds)
- Enricher failures are recorded in `context.errors` but do not stop the pipeline

### CloudTrail Enrichers

| Enricher | Stage | Purpose |
|---|---|---|
| `PrincipalIdentityEnricher` | 0 | Extracts `Principal` from `userIdentity` (ARN, account ID, session context) |
| `PrincipalHistoryEnricher` | 1 (parallel) | CloudTrail `lookup_events` for this principal in the last 24h |
| `WriteFilterEnricher` | 1 (parallel) | Filters to successful write/mutate API calls only |
| `ObjectInspectionEnricher` | 2 | Inspects referenced S3/IAM resources for sensitivity |

### InProcessTTLCache (`tengen/enrichers/cache.py`)
LRU+TTL cache backed by `OrderedDict`. Injectable clock for deterministic testing. Configurable max size (default: 1024 entries) and TTL per enricher.

---

## Containment

All containment functions follow this contract:
- Accept `finding_json: str` as the first argument (the full Finding for context)
- Return a JSON string: `{"action": str, "status": "success" | "error", ...details}`
- Never raise exceptions — all errors are caught and returned as JSON

### AWS Containment (`tengen/tools/containment/aws_containment.py`)

| Function | Action |
|---|---|
| `disable_iam_access_key(finding_json, access_key_id)` | Sets IAM access key status to `Inactive` |
| `revoke_sts_sessions(finding_json, username)` | Attaches a `DenyAll` inline policy with `DateLessThan` condition to invalidate active STS sessions |
| `modify_security_group_deny(finding_json, group_id, source_ip)` | Revokes all ingress permissions for the source IP from the security group |
| `disable_iam_user(finding_json, username)` | Disables all access keys for the user |

### GCP Containment (`tengen/tools/containment/gcp_containment.py`)

| Function | Action |
|---|---|
| `disable_service_account(finding_json, sa_email, project_id)` | Calls IAM `projects.serviceAccounts.disable` |
| `add_vpc_firewall_deny(finding_json, project_id, source_ip, network)` | Inserts a `priority=900` INGRESS DENY ALL rule for the source IP |

### Azure Containment (`tengen/tools/containment/azure_containment.py`)

| Function | Action |
|---|---|
| `disable_azure_ad_user(finding_json, user_id)` | PATCH `https://graph.microsoft.com/v1.0/users/{user_id}` with `accountEnabled: false` |
| `revoke_azure_refresh_tokens(finding_json, user_id)` | POST `revokeSignInSessions` on Microsoft Graph API |

Both Azure functions obtain a fresh OAuth2 `client_credentials` token before each call using `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`.

### Kubernetes Containment (`tengen/tools/containment/k8s_containment.py`)

| Function | Action |
|---|---|
| `cordon_node(finding_json, node_name)` | PATCH node spec `unschedulable: true` |
| `delete_pod(finding_json, namespace, pod_name)` | Deletes the pod immediately (no grace period) |
| `delete_service_account_token(finding_json, namespace, secret_name)` | Deletes the SA token secret |
| `create_network_policy_deny(finding_json, namespace, label_selector)` | Creates a `tengen-quarantine` NetworkPolicy denying all Ingress and Egress for matching pods |

All K8s functions auto-detect in-cluster config, falling back to `K8S_KUBECONFIG` or default `~/.kube/config`.

---

## External Enrichment

All external enrichment functions are in `tengen/tools/enrichment.py`. They all return JSON strings and never raise exceptions.

### `lookup_ip_reputation(ip: str) -> str`
Primary: AbuseIPDB (`ABUSE_IPDB_KEY`) — returns abuse confidence score, country, ISP, total reports, Tor status.
Fallback: VirusTotal (`VT_API_KEY`) — returns malicious engine count ratio as abuse score.

Returns: `{ip, abuse_score, country, isp, total_reports, is_tor, source}`

### `lookup_ip_geo(ip: str) -> str`
ipinfo.io (`IPINFO_TOKEN` optional — free tier works without it).
Returns: `{ip, city, region, country, org, timezone, loc}`

### `lookup_domain(domain: str) -> str`
SecurityTrails API (`SECURITYTRAILS_API_KEY`).
Returns: `{domain, registrar, created, expires, name_servers, categories, alexa_rank, source}`

### `lookup_file_hash(sha256: str) -> str`
VirusTotal (`VT_API_KEY`).
Returns: `{sha256, malicious, suspicious, harmless, undetected, names, tags, type_description, source}`

### `lookup_user_context(identifier: str) -> str`
Primary: Okta (`OKTA_API_TOKEN` + `OKTA_DOMAIN`) — returns full user profile, MFA status, account status, last login.
Fallback: Azure Graph (`AZURE_TENANT_ID` + `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET`).
Returns: `{id, email, display_name, department, title, manager, mfa_enrolled, last_login, account_enabled, groups, source}`

### `lookup_asset_context(asset_id: str) -> str`
Primary: CMDB REST API (`CMDB_ENDPOINT` + optional `CMDB_TOKEN`).
Fallback for AWS ARNs: AWS Config `get_resource_config_history`.
Returns: `{asset_id, name, type, owner, env, tags, compliance_violations, source}`

---

## MCP Servers

All MCP servers use stdio transport and are compatible with any MCP client. Start them with `python -m tengen.mcp_servers.<server_name>`.

### `cloudtrail_server.py`
Tools: `get_cloudtrail_events(start_time, end_time, event_name?, max_results?)`, `get_cloudtrail_event_by_id(event_id)`
Requires: standard AWS credentials (boto3)

### `gcp_audit_server.py`
Tools: `get_gcp_audit_logs(project_id, start_time, end_time, principal_email?, max_results?)`, `get_gcp_audit_log_by_id(log_name, insert_id)`
Requires: `GCP_PROJECT_ID`, Google Application Default Credentials

### `azure_activity_server.py`
Tools: `get_azure_activity_logs(subscription_id, start_time, end_time, resource_group?, caller?, max_results?)`, `get_azure_activity_log_by_correlation_id(subscription_id, correlation_id)`, `get_azure_signin_logs(start_time, end_time, user_principal_name?, max_results?)`
Requires: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`

### `crowdstrike_server.py`
Tools: `get_cs_detections(start_time, end_time, severity?, max_results?)`, `get_cs_detection_by_id(detection_id)`, `get_cs_events(event_type?, start_time?, end_time?, max_results?)`, `get_cs_incidents(start_time, end_time, state?, max_results?)`
Requires: `CROWDSTRIKE_CLIENT_ID`, `CROWDSTRIKE_CLIENT_SECRET`, `CROWDSTRIKE_BASE_URL`

### `k8s_audit_server.py`
Tools: `get_k8s_audit_events(namespace?, verb?, user?, resource?, start_time?, max_results?)`, `get_k8s_pod_events(namespace, pod_name)`, `get_k8s_secrets_access(namespace?, start_time?, max_results?)`, `get_k8s_privileged_operations(namespace?, start_time?, max_results?)`
Requires: in-cluster config or `K8S_KUBECONFIG`

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
| `GET /api/runbooks` | All discovered runbook classes and their source queues |
| `GET /api/agents` | LLM agent activity from metrics (which agents ran, error counts) |

### Dashboard UI (`tengen/dashboard/static/index.html`)
Dark-themed single-page application. Polls all `/api/*` endpoints every 10 seconds. Displays:
- Queue depth chart for all RabbitMQ queues
- Route match counts (which routes are getting the most traffic)
- Runbook success/error rates
- Containment action counts
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
| `runbook_success` | Runbook | `{runbook, source, duration_ms}` |
| `runbook_error` | Runbook | `{runbook, error}` |
| `enricher_duration_ms` | Enricher | `{enricher_name, duration_ms}` |
| `containment_executed` | Containment | `{action, cloud, severity}` |
| `containment_skipped` | Containment | `{reason, severity}` |
| `enrichment_latency_ms` | Enrichment | `{lookup_type, duration_ms}` |
| `enrichment_error` | Enrichment | `{lookup_type, error}` |
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

### External Enrichment

| Variable | Description |
|---|---|
| `ABUSE_IPDB_KEY` | AbuseIPDB API key for IP reputation |
| `VT_API_KEY` | VirusTotal API key (IP reputation fallback + file hash lookup) |
| `IPINFO_TOKEN` | ipinfo.io token (optional — free tier works without it) |
| `SECURITYTRAILS_API_KEY` | SecurityTrails API key for domain lookups |
| `OKTA_API_TOKEN` | Okta SSWS API token for user context |
| `OKTA_DOMAIN` | Okta org domain (e.g. `your-org.okta.com`) |
| `CMDB_ENDPOINT` | CMDB REST API base URL for asset context |
| `CMDB_TOKEN` | CMDB Bearer token (optional) |

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
pytest tests/test_normalizers.py    # Source detection + all 7 normalizers (9 tests)
pytest tests/test_triage.py         # Correlation, scoring, suppression (14 tests)
pytest tests/test_containment.py    # Cloud containment tools — mocked (11 tests)
pytest tests/test_enrichment.py     # External lookups — mocked HTTP (8 tests)
pytest tests/test_models.py         # Pydantic model validation
pytest tests/test_cloudtrail_runbook.py
pytest tests/test_gcp_audit_runbook.py
pytest tests/test_orchestrator.py
pytest tests/test_router.py

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
7. **Create YAML runbooks** in `runbooks/<source>/`
8. **Optionally create a runbook agent** in `tengen/agents/<source>_runbook.py` and add it as a sub-agent of `router_agent`
9. **Add tests** in `tests/test_normalizers.py`

### Adding a new runbook (no code required)

Just create a YAML file in the appropriate `runbooks/<provider>/` directory following the runbook format. The `runbook_loader.py` will discover it automatically.

### Adding a new containment action

1. Add the function to the appropriate `tengen/tools/containment/<cloud>_containment.py`
2. Add a wrapper function and `FunctionTool` in `tengen/agents/containment.py`
3. Update the ContainmentAgent instruction to describe when to use it
4. Add a test in `tests/test_containment.py`

### Adding a new external enrichment lookup

1. Add the function to `tengen/tools/enrichment.py` (return JSON string, never raise)
2. Add a `FunctionTool` in `tengen/agents/enrichment_agent.py`
3. Update the EnrichmentAgent instruction to describe when to call it
4. Add the env var to `tengen/config.py` and `.env.example`

### Adding a new MCP server

1. Create `tengen/mcp_servers/<source>_server.py` following the existing server pattern
2. Implement `list_tools()` and `call_tool()` handlers
3. Add `async def main()` with `stdio_server` transport
4. Optionally wire as a tool source in the QueryAgent

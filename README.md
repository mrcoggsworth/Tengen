# Tengen

A production-grade agentic security harness built on Google ADK. Tengen ingests security events from any cloud or EDR source, normalizes them into a universal schema, triages and correlates them into incidents, executes real containment actions, enriches findings with external threat intelligence, and forwards results to your SIEM — all driven by LLM agents.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  INGESTION                                                       │
│  Kafka · SQS/SNS · Pub/Sub · Splunk ES · Universal HTTP         │
│                        ↓ RabbitMQ [alerts]                      │
├─────────────────────────────────────────────────────────────────┤
│  NORMALIZATION  (NormalizerAgent)                                │
│  AWS · GCP · Azure · CrowdStrike · K8s · Firewall · DDoS        │
│                        ↓ NormalizedEvent                        │
├─────────────────────────────────────────────────────────────────┤
│  TRIAGE  (TriageAgent)                                           │
│  correlate → score → suppress                                   │
│                        ↓ Incident                               │
├─────────────────────────────────────────────────────────────────┤
│  ROUTING  (RouterAgent + RouteRegistry)                          │
│  deterministic first-match → runbook queue                      │
├─────────────────────────────────────────────────────────────────┤
│  RUNBOOKS  (per-source LlmAgents)                               │
│  CloudTrail · GCP Audit · Azure Activity · CrowdStrike · K8s   │
│                        ↓ Finding                                │
├─────────────────────────────────────────────────────────────────┤
│  CONTAINMENT  (ContainmentAgent)                                 │
│  CRITICAL/HIGH → auto-execute · MEDIUM → analyst approval       │
│  AWS IAM/SG · GCP IAM/VPC · Azure AD/Graph · Kubernetes        │
├─────────────────────────────────────────────────────────────────┤
│  ENRICHMENT  (EnrichmentAgent)                                   │
│  AbuseIPDB · VirusTotal · ipinfo.io · Okta · Azure Graph · CMDB│
├─────────────────────────────────────────────────────────────────┤
│  FORWARDING                                                      │
│  Splunk HEC (batched, retrying) · PagerDuty · DLQ forwarder     │
└─────────────────────────────────────────────────────────────────┘

QueryAgent ── analyst NL queries across all sources (ad-hoc)
Dashboard  ── FastAPI live UI: queue depths, routes, metrics
```

## Agent Responsibilities

| Agent | Role |
|---|---|
| **OrchestratorAgent** | Drives the full 6-step pipeline for every incoming event |
| **NormalizerAgent** | Detects source type and normalizes to `NormalizedEvent` |
| **TriageAgent** | Correlates events into incidents, scores priority, suppresses noise |
| **RouterAgent** | Pure-function route matching → correct runbook agent |
| **CloudTrailRunbookAgent** | AWS CloudTrail investigation + Finding |
| **GCPAuditRunbookAgent** | GCP Audit Log investigation + Finding |
| **AzureRunbookAgent** | Azure Activity Log investigation + Finding |
| **EDRRunbookAgent** | CrowdStrike detection investigation + Finding |
| **K8sRunbookAgent** | Kubernetes audit log investigation + Finding |
| **ContainmentAgent** | Executes real cloud containment actions |
| **EnrichmentAgent** | External threat intel lookups |
| **QueryAgent** | Analyst-facing ad-hoc NL security queries |
| **ForwarderAgent** | Routes enriched Findings to Splunk / PagerDuty |

## Project Structure

```
tengen/
├── agents/          # LlmAgent definitions (orchestrator, triage, containment, etc.)
├── consumers/       # BaseConsumer + SQS, Kafka, Pub/Sub, Splunk ES, Universal HTTP
├── dashboard/       # FastAPI observability UI + MetricsStore (SQLite)
├── enrichers/       # EnricherPipeline: staged async, per-enricher timeout, TTL cache
├── forwarder/       # SplunkHECClient (batched, retrying) + DLQ forwarder
├── mcp_servers/     # MCP stdio servers: CloudTrail, GCP Audit, Azure, CrowdStrike, K8s
├── metrics/         # MetricsEmitter (fire-and-forget, never raises)
├── models/          # Pydantic v2 frozen models: Alert, NormalizedEvent, Incident, Finding
├── queue/           # RabbitMQ publisher/consumer + queue name constants
├── routing/         # RouteRegistry (pure-function first-match) + 8 route matchers
├── runbooks/        # BaseRunbook + 5 runbook pods
└── tools/
    ├── containment/ # AWS, GCP, Azure, K8s containment actions
    ├── normalizers/ # Per-source normalizers + source detection registry
    ├── enrichment.py        # External threat intel lookups
    └── triage_tools.py      # correlate_event, score_incident, check_suppression
runbooks/
├── aws/             # CloudTrail YAML runbooks
├── gcp/             # GCP Audit YAML runbooks
├── azure/           # Azure Activity YAML runbooks (unauthorized_access, privilege_escalation, suspicious_signin)
├── edr/             # CrowdStrike YAML runbooks (malware_detection, lateral_movement, credential_dumping)
├── k8s/             # Kubernetes YAML runbooks (privileged_container, secrets_access, anomalous_exec)
└── network/         # Network YAML runbooks (firewall_block_surge, ddos_inbound)
docker/
└── docker-compose.yml  # RabbitMQ, Kafka, LocalStack, Pub/Sub emulator
tests/               # 29 unit tests
```

## Quick Start

```bash
pip install -e ".[dev]"
cp .env.example .env
# Fill in credentials — at minimum GOOGLE_API_KEY and RABBITMQ_URL
pytest
```

### Start the local stack

```bash
docker compose -f docker/docker-compose.yml up -d rabbitmq localstack
```

### Run the pipeline components

```bash
# Event router (reads [alerts] queue, routes to runbook queues)
tengen-router

# Enriched-alert + DLQ forwarder (reads [enriched] and [alerts.dlq])
tengen-forwarder

# Observability dashboard → http://localhost:8080
tengen-dashboard

# Universal HTTP ingest endpoint → POST http://localhost:8088/ingest
tengen-ingest
```

### Send an event through the pipeline

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

raw_event = {"eventVersion": "1.08", "eventSource": "iam.amazonaws.com", ...}

asyncio.run(runner.run_async(
    user_id="soar",
    session_id="s1",
    new_message={"role": "user", "parts": [{"text": json.dumps(raw_event)}]},
))
```

### Ad-hoc analyst queries

```python
from tengen.agents.query import query_agent

# "Find all API calls from 1.2.3.4 in CloudTrail over the last 24 hours"
# "Show CrowdStrike CRITICAL detections this week"
# "Correlate this IP across CloudTrail and CrowdStrike"
```

## Supported Log Sources

| Source | Normalizer | Runbook Agent | MCP Server | Runbooks |
|---|---|---|---|---|
| AWS CloudTrail | ✅ | ✅ | ✅ | root_account_usage, unauthorized_api_call |
| AWS GuardDuty | ✅ (routed) | ✅ | ✅ | — |
| GCP Audit Log | ✅ | ✅ | ✅ | admin_activity, data_access |
| Azure Activity | ✅ | ✅ | ✅ | unauthorized_access, privilege_escalation, suspicious_signin |
| CrowdStrike EDR | ✅ | ✅ | ✅ | malware_detection, lateral_movement, credential_dumping |
| Kubernetes Audit | ✅ | ✅ | ✅ | privileged_container, secrets_access, anomalous_exec |
| Firewall Deny | ✅ | — | — | firewall_block_surge |
| DDoS Flow | ✅ | — | — | ddos_inbound |

## Containment Actions

| Cloud | Actions |
|---|---|
| **AWS** | `disable_iam_access_key`, `revoke_sts_sessions`, `modify_security_group_deny`, `disable_iam_user` |
| **GCP** | `disable_service_account`, `add_vpc_firewall_deny` |
| **Azure** | `disable_azure_ad_user`, `revoke_azure_refresh_tokens` |
| **Kubernetes** | `cordon_node`, `delete_pod`, `delete_service_account_token`, `create_network_policy_deny` |

CRITICAL/HIGH severity → auto-executed. MEDIUM → flagged for analyst approval. LOW/INFO → skipped.

## External Enrichment

| Lookup | Provider | Env Var |
|---|---|---|
| IP reputation | AbuseIPDB / VirusTotal | `ABUSE_IPDB_KEY` / `VT_API_KEY` |
| IP geolocation | ipinfo.io | `IPINFO_TOKEN` |
| Domain info | SecurityTrails | `SECURITYTRAILS_API_KEY` |
| File hash | VirusTotal | `VT_API_KEY` |
| User context | Okta / Azure Graph | `OKTA_API_TOKEN` + `OKTA_DOMAIN` |
| Asset context | CMDB / AWS Config | `CMDB_ENDPOINT` |

## MCP Servers

| Server | Tools |
|---|---|
| `cloudtrail_server` | `get_cloudtrail_events`, `get_cloudtrail_event_by_id` |
| `gcp_audit_server` | `get_gcp_audit_logs`, `get_gcp_audit_log_by_id` |
| `azure_activity_server` | `get_azure_activity_logs`, `get_azure_activity_log_by_correlation_id`, `get_azure_signin_logs` |
| `crowdstrike_server` | `get_cs_detections`, `get_cs_detection_by_id`, `get_cs_events`, `get_cs_incidents` |
| `k8s_audit_server` | `get_k8s_audit_events`, `get_k8s_pod_events`, `get_k8s_secrets_access`, `get_k8s_privileged_operations` |

## Configuration

Copy `.env.example` to `.env` and fill in the values for the integrations you need. At minimum:

```bash
GOOGLE_API_KEY=...       # Gemini API key for LLM agents
RABBITMQ_URL=...         # amqp://guest:guest@localhost:5672/
```

See `.env.example` for the full list of ~40 configuration options.

## Running Tests

```bash
pytest                          # all 29 unit tests
pytest tests/test_normalizers.py   # normalizer pipeline
pytest tests/test_triage.py        # correlation, scoring, suppression
pytest tests/test_containment.py   # containment tools (mocked)
pytest tests/test_enrichment.py    # external lookups (mocked)
```

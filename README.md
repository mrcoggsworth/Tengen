# Tengen

Google ADK-based SOAR (Security Orchestration, Automation, and Response) skeleton for cloud security automation. The spiritual counterpart to LogPose.

## Agent Pipeline

```
OrchestratorAgent
    └── RouterAgent
            ├── CloudTrailRunbookAgent   (AWS events)
            └── GCPAuditRunbookAgent     (GCP events)
    └── ForwarderAgent
```

### Agent Responsibilities

| Agent | Role |
|---|---|
| **OrchestratorAgent** | Ingests raw cloud events, parses and validates alerts, coordinates the full response pipeline |
| **RouterAgent** | Detects cloud provider and hands off to the appropriate runbook agent |
| **CloudTrailRunbookAgent** | Enriches and executes AWS CloudTrail runbooks, produces structured Findings |
| **GCPAuditRunbookAgent** | Enriches and executes GCP Audit Log runbooks, produces structured Findings |
| **ForwarderAgent** | Routes enriched Findings to SIEM and/or PagerDuty based on severity |

## Project Structure

```
tengen/
├── agents/          # LlmAgent definitions
├── tools/           # Pure-Python tool functions
├── models/          # Pydantic data models (Alert, Finding, Runbook)
└── mcp_servers/     # MCP stdio servers for CloudTrail and GCP Audit Logs
runbooks/
├── aws/             # YAML runbooks for AWS event types
└── gcp/             # YAML runbooks for GCP event types
tests/               # 17 unit tests
```

## Quick Start

```bash
pip install -e ".[dev]"
cp .env.example .env
# fill in .env values
pytest
```

## Running an Alert Through the Pipeline

```python
import asyncio
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from tengen.agents.orchestrator import orchestrator_agent

runner = Runner(
    agent=orchestrator_agent,
    app_name="tengen",
    session_service=InMemorySessionService(),
)

# raw_event is a CloudTrail or GCP Audit Log JSON dict
asyncio.run(runner.run_async(
    user_id="soar",
    session_id="s1",
    new_message={"role": "user", "parts": [{"text": f"Process this AWS event: {raw_event_json}"}]},
))
```

## MCP Servers

| Server | Transport | Description |
|---|---|---|
| `tengen.mcp_servers.cloudtrail_server` | stdio | Queries AWS CloudTrail via boto3 |
| `tengen.mcp_servers.gcp_audit_server` | stdio | Queries GCP Audit Logs via google-cloud-logging |

## Runbooks

Runbooks are YAML files in `runbooks/<provider>/<event_type_slug>.yaml`. Add new runbooks by creating new YAML files — no code changes required.

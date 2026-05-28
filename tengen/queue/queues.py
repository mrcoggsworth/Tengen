from __future__ import annotations

# All RabbitMQ queue name constants — single source of truth.
# Never use bare string literals for queue names outside this file.

# Phase I: ingestion → normalization
QUEUE_ALERTS: str = "alerts"

# Phase II: normalized events → triage
QUEUE_NORMALIZED: str = "normalized"

# Phase III: triaged incidents → routing
QUEUE_INCIDENTS: str = "incidents"

# Phase IV: per-runbook destination queues
QUEUE_RUNBOOK_CLOUDTRAIL: str = "runbook.cloudtrail"
QUEUE_RUNBOOK_GUARDDUTY: str = "runbook.guardduty"
QUEUE_RUNBOOK_EKS: str = "runbook.eks"
QUEUE_RUNBOOK_GCP_EVENT_AUDIT: str = "runbook.gcp.event_audit"
QUEUE_RUNBOOK_AZURE_ACTIVITY: str = "runbook.azure.activity"
QUEUE_RUNBOOK_CROWDSTRIKE: str = "runbook.crowdstrike"
QUEUE_RUNBOOK_K8S: str = "runbook.k8s"
QUEUE_RUNBOOK_FIREWALL: str = "runbook.firewall"
QUEUE_RUNBOOK_TEST: str = "runbook.test"

# Phase V: enriched runbook output → forwarding
QUEUE_ENRICHED: str = "enriched"

# Dead-letter queue — unroutable or failed alerts, forwarded to SIEM
QUEUE_DLQ: str = "alerts.dlq"

# Metrics — MetricsEmitter publishes; dashboard consumes
QUEUE_METRICS: str = "tengen.metrics"

ALL_RUNBOOK_QUEUES: tuple[str, ...] = (
    QUEUE_RUNBOOK_CLOUDTRAIL,
    QUEUE_RUNBOOK_GUARDDUTY,
    QUEUE_RUNBOOK_EKS,
    QUEUE_RUNBOOK_GCP_EVENT_AUDIT,
    QUEUE_RUNBOOK_AZURE_ACTIVITY,
    QUEUE_RUNBOOK_CROWDSTRIKE,
    QUEUE_RUNBOOK_K8S,
    QUEUE_RUNBOOK_FIREWALL,
    QUEUE_RUNBOOK_TEST,
)

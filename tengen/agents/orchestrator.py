"""OrchestratorAgent — top-level pipeline: ingest → normalize → triage → route → contain → enrich → forward."""
from __future__ import annotations

import json
import uuid

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

from ..config import settings
from .containment import containment_agent
from .enrichment_agent import enrichment_agent
from .forwarder import forwarder_agent
from .normalizer import normalizer_agent
from .router import router_agent
from .triage import triage_agent


def _normalize_event(raw_event_json: str) -> str:
    """Normalize a raw log event into a NormalizedEvent JSON.

    Accepts raw JSON from any source (CloudTrail, GCP Audit, Azure, CrowdStrike, K8s, firewall, DDoS).
    Returns NormalizedEvent JSON or error JSON.
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
        if event.source_type.value == "unknown":
            return "invalid: source_type is unknown"
        if not event.event_name:
            return "invalid: event_name is empty"
        return "valid"
    except Exception as exc:
        return f"invalid: {exc}"


def _emit_metric(event_name: str, data_json: str = "{}") -> str:
    """Emit a metric event for observability. Returns 'ok' or 'error: <msg>'."""
    try:
        from ..metrics.emitter import MetricsEmitter
        emitter = MetricsEmitter()
        emitter.emit(event_name, json.loads(data_json))
        return "ok"
    except Exception as exc:
        return f"error: {exc}"


def _legacy_parse_alert(raw_event_json: str, provider: str) -> str:
    """Legacy: parse a raw cloud event into an Alert using the old parsers.

    provider: 'aws' or 'gcp'. Kept for backwards compatibility.
    """
    from ..tools.alert_parser import parse_cloudtrail_event, parse_gcp_audit_event
    raw_event = json.loads(raw_event_json)
    if provider == "aws":
        alert = parse_cloudtrail_event(raw_event)
    elif provider == "gcp":
        alert = parse_gcp_audit_event(raw_event)
    else:
        from ..models.alert import Alert, AlertSeverity
        alert = Alert(
            source="unknown",
            raw_payload=raw_event,
            severity=AlertSeverity.INFO,
            event_type="Unknown",
            raw_event=raw_event,
            timestamp="",
        )
    return alert.model_dump_json()


orchestrator_agent = LlmAgent(
    name="orchestrator_agent",
    model=settings.model_name,
    description=(
        "Top-level Tengen security agentic harness orchestrator. "
        "Drives the full pipeline: normalize → triage → route → runbook → contain → enrich → forward."
    ),
    instruction=(
        "You are the OrchestratorAgent for Tengen — a multi-cloud security agentic harness. "
        "When given a raw security event JSON, execute the full pipeline: "
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
        "STEP 3 — ROUTE & RUNBOOK: "
        "  Transfer to router_agent with the NormalizedEvent JSON. "
        "  Receive a Finding JSON from the runbook agent. "
        "  Call emit_metric('runbook_success', {source: <source_type>}). "
        ""
        "STEP 4 — CONTAIN: "
        "  Transfer to containment_agent with the Finding JSON. "
        "  Receive containment result. "
        "  Call emit_metric('containment_executed', {actions: <count>}). "
        ""
        "STEP 5 — ENRICH: "
        "  Transfer to enrichment_agent with the Finding JSON. "
        "  Receive the enriched Finding JSON. "
        ""
        "STEP 6 — FORWARD: "
        "  Transfer to forwarder_agent with the enriched Finding JSON. "
        ""
        "FINAL RESPONSE: Return a plain-text summary: "
        "  event_id, source_type, incident priority score, finding title, "
        "  severity, containment actions taken (or 'none'), forwarding status."
    ),
    tools=[
        FunctionTool(func=_normalize_event),
        FunctionTool(func=_validate_normalized_event),
        FunctionTool(func=_emit_metric),
        FunctionTool(func=_legacy_parse_alert),
    ],
    sub_agents=[
        normalizer_agent,
        triage_agent,
        router_agent,
        containment_agent,
        enrichment_agent,
        forwarder_agent,
    ],
)

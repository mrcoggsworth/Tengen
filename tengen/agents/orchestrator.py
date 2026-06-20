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

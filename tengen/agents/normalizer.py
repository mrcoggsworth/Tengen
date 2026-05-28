"""NormalizerAgent — detects log source type and normalizes raw events into NormalizedEvent."""
from __future__ import annotations

import json

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

from ..config import settings


def _detect_and_normalize(raw_event_json: str) -> str:
    """Detect source type and normalize a raw log event into a NormalizedEvent JSON.

    Accepts any raw event dict. Returns a NormalizedEvent JSON or an error JSON.
    """
    from ..tools.normalizers.registry import normalize
    try:
        raw_event = json.loads(raw_event_json)
        normalized = normalize(raw_event)
        return normalized.model_dump_json()
    except Exception as exc:
        return json.dumps({"error": str(exc), "raw_event_preview": raw_event_json[:200]})


def _detect_source_type(raw_event_json: str) -> str:
    """Detect the log source type without full normalization.

    Returns the LogSourceType string: 'aws', 'gcp', 'azure', 'crowdstrike',
    'firewall', 'ddos', 'k8s', 'openshift', or 'unknown'.
    """
    from ..tools.normalizers.registry import detect_source_type
    try:
        raw_event = json.loads(raw_event_json)
        return detect_source_type(raw_event).value
    except Exception as exc:
        return f"error: {exc}"


normalizer_agent = LlmAgent(
    name="normalizer_agent",
    model=settings.model_name,
    description=(
        "Normalizes raw security log events from any source (AWS, GCP, Azure, "
        "CrowdStrike, Kubernetes, firewall, DDoS) into a universal NormalizedEvent schema."
    ),
    instruction=(
        "You are the NormalizerAgent. When given a raw security event JSON: "
        "1. Call detect_source_type to identify the log source. "
        "2. Call detect_and_normalize to produce a NormalizedEvent. "
        "3. If normalization fails, return the error JSON as-is. "
        "4. Otherwise return only the NormalizedEvent JSON — no commentary. "
        "The NormalizedEvent will be consumed by the TriageAgent."
    ),
    tools=[
        FunctionTool(func=_detect_source_type),
        FunctionTool(func=_detect_and_normalize),
    ],
)

"""TriageAgent — correlates NormalizedEvents into Incidents, scores, and suppresses."""
from __future__ import annotations

import json

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

from ..config import settings


def _correlate_event(event_json: str, incident_store_json: str) -> str:
    """Correlate a NormalizedEvent into an existing Incident or create a new one.

    incident_store_json: JSON array of Incident objects from the current session.
    Returns the updated or newly created Incident JSON.
    """
    from ..tools.triage_tools import correlate_event
    return correlate_event(event_json, incident_store_json)


def _score_incident(incident_json: str) -> str:
    """Compute a priority score for an Incident.

    Returns the float score as a JSON string, e.g. "14.7".
    """
    from ..tools.triage_tools import score_incident
    score = score_incident(incident_json)
    return json.dumps(score)


def _check_suppression(incident_json: str, suppression_rules_json: str = "{}") -> str:
    """Determine whether an Incident should be suppressed.

    Returns JSON: {"suppressed": bool, "reason": str}.
    suppression_rules_json keys: min_priority_score, known_good_identities.
    """
    from ..tools.triage_tools import check_suppression
    return check_suppression(incident_json, suppression_rules_json)


def _update_incident_score(incident_json: str, score: float) -> str:
    """Return the Incident JSON with the priority_score field updated."""
    try:
        from ..models.incident import Incident
        incident = Incident.model_validate_json(incident_json)
        updated = incident.model_copy(update={"priority_score": score})
        return updated.model_dump_json()
    except Exception as exc:
        return json.dumps({"error": str(exc)})


triage_agent = LlmAgent(
    name="triage_agent",
    model=settings.model_name,
    description=(
        "Triages normalized security events: correlates events into incidents, "
        "computes priority scores, and suppresses low-fidelity noise."
    ),
    instruction=(
        "You are the TriageAgent. You receive a NormalizedEvent JSON and an "
        "incident_store JSON (array of open Incidents from this session). "
        "Follow these steps: "
        "1. Call correlate_event with the event and incident store to group it "
        "   into an existing or new Incident. "
        "2. Call score_incident on the resulting Incident to compute a priority score. "
        "3. Call update_incident_score to write the score back into the Incident. "
        "4. Call check_suppression with the scored Incident. "
        "   If suppressed=true, return JSON: "
        '   {"suppressed": true, "reason": "<reason>", "incident": <incident_json>}. '
        "5. If not suppressed, return JSON: "
        '   {"suppressed": false, "incident": <incident_json>, "score": <score>}. '
        "Do not take any further action — routing is handled by the orchestrator."
    ),
    tools=[
        FunctionTool(func=_correlate_event),
        FunctionTool(func=_score_incident),
        FunctionTool(func=_check_suppression),
        FunctionTool(func=_update_incident_score),
    ],
)

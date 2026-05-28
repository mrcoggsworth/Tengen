"""Triage tools: correlation, scoring, and suppression logic."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from tengen.models.alert import AlertSeverity
from tengen.models.incident import Incident, IncidentStatus
from tengen.models.normalized_event import NormalizedEvent

# Source-type priority weights for priority scoring
_SOURCE_WEIGHTS: dict[str, float] = {
    "crowdstrike": 1.5,
    "aws": 1.2,
    "gcp": 1.2,
    "azure": 1.2,
    "k8s": 1.3,
    "openshift": 1.3,
    "firewall": 0.9,
    "ddos": 1.0,
    "unknown": 0.5,
}

_SEVERITY_SCORES: dict[AlertSeverity, float] = {
    AlertSeverity.CRITICAL: 10.0,
    AlertSeverity.HIGH: 7.0,
    AlertSeverity.MEDIUM: 4.0,
    AlertSeverity.LOW: 2.0,
    AlertSeverity.INFO: 0.5,
}

_CORRELATION_WINDOW_MINUTES = 15


def correlate_event(
    event_json: str,
    incident_store_json: str,
) -> str:
    """Group a NormalizedEvent into an existing Incident or create a new one.

    Returns the updated/new Incident as JSON.
    Matching criteria: same actor.identity + same source_type within the
    correlation window.
    """
    event = NormalizedEvent.model_validate_json(event_json)
    store: list[dict[str, Any]] = json.loads(incident_store_json) if incident_store_json else []

    window_cutoff = datetime.now(tz=timezone.utc) - timedelta(minutes=_CORRELATION_WINDOW_MINUTES)

    # Find an open incident in the window with the same actor+source
    for incident_data in store:
        incident = Incident.model_validate(incident_data)
        if incident.suppressed or incident.status in (IncidentStatus.CLOSED, IncidentStatus.SUPPRESSED):
            continue
        if not incident.events:
            continue
        first_event = incident.events[0]
        try:
            updated_at = datetime.fromisoformat(incident.updated_at)
        except Exception:
            continue
        if updated_at < window_cutoff:
            continue
        if (
            first_event.actor.identity == event.actor.identity
            and first_event.source_type == event.source_type
        ):
            # Append to existing incident
            updated = Incident(
                incident_id=incident.incident_id,
                events=list(incident.events) + [event],
                findings=incident.findings,
                status=IncidentStatus.TRIAGING,
                priority_score=incident.priority_score,
                suppressed=incident.suppressed,
                suppression_reason=incident.suppression_reason,
                created_at=incident.created_at,
                updated_at=datetime.now(tz=timezone.utc).isoformat(),
                labels=incident.labels,
            )
            return updated.model_dump_json()

    # No match — create new incident
    new_incident = Incident(
        incident_id=str(uuid.uuid4()),
        events=[event],
        status=IncidentStatus.OPEN,
        created_at=datetime.now(tz=timezone.utc).isoformat(),
        updated_at=datetime.now(tz=timezone.utc).isoformat(),
    )
    return new_incident.model_dump_json()


def score_incident(incident_json: str) -> float:
    """Compute a priority score for an incident.

    score = max_severity_score × source_weight × recurrence_factor
    """
    incident = Incident.model_validate_json(incident_json)
    if not incident.events:
        return 0.0

    max_severity = max(
        _SEVERITY_SCORES.get(e.severity, 0.5) for e in incident.events
    )
    source_weight = _SOURCE_WEIGHTS.get(incident.events[0].source_type.value, 1.0)
    recurrence_factor = min(1.0 + (len(incident.events) - 1) * 0.2, 3.0)

    # Boost for privileged actors
    if any(e.actor.is_privileged for e in incident.events):
        recurrence_factor *= 1.5

    return round(max_severity * source_weight * recurrence_factor, 2)


def check_suppression(
    incident_json: str,
    suppression_rules_json: str = "{}",
) -> str:
    """Determine whether an incident should be suppressed.

    Returns a JSON object: {"suppressed": bool, "reason": str}
    """
    incident = Incident.model_validate_json(incident_json)
    rules: dict[str, Any] = json.loads(suppression_rules_json) if suppression_rules_json else {}

    # Rule 1: below minimum priority score
    min_score = float(rules.get("min_priority_score", 1.0))
    if incident.priority_score < min_score:
        return json.dumps({"suppressed": True, "reason": f"priority_score {incident.priority_score} below threshold {min_score}"})

    # Rule 2: known-good service accounts
    known_good = rules.get("known_good_identities", [])
    for event in incident.events:
        if event.actor.identity in known_good:
            return json.dumps({"suppressed": True, "reason": f"known_good_identity: {event.actor.identity}"})

    # Rule 3: INFO-only events with low recurrence
    if all(e.severity == AlertSeverity.INFO for e in incident.events) and len(incident.events) < 3:
        return json.dumps({"suppressed": True, "reason": "info_only_low_recurrence"})

    return json.dumps({"suppressed": False, "reason": ""})

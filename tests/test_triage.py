"""Unit tests for triage tools: correlate_event, score_incident, check_suppression."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest

from tengen.models.alert import AlertSeverity
from tengen.models.incident import Incident, IncidentStatus
from tengen.models.normalized_event import (
    ActorContext, LogSourceType, NetworkContext, NormalizedEvent,
    Outcome, TargetContext,
)
from tengen.tools.triage_tools import check_suppression, correlate_event, score_incident


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_event(
    identity: str = "alice",
    source_type: LogSourceType = LogSourceType.AWS,
    severity: AlertSeverity = AlertSeverity.HIGH,
    is_privileged: bool = False,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        source_type=source_type,
        log_type="cloudtrail",
        actor=ActorContext(identity=identity, identity_type="IAMUser", is_privileged=is_privileged),
        target=TargetContext(resource_id="arn:aws:s3:::bucket"),
        network=NetworkContext(src_ip="1.2.3.4"),
        outcome=Outcome.SUCCESS,
        event_name="DeleteBucket",
        severity=severity,
        raw_event={},
        tags=[],
        labels={},
    )


def _make_incident(events: list[NormalizedEvent], score: float = 0.0) -> Incident:
    return Incident(
        incident_id=str(uuid.uuid4()),
        events=events,
        status=IncidentStatus.OPEN,
        priority_score=score,
        created_at=datetime.now(tz=timezone.utc).isoformat(),
        updated_at=datetime.now(tz=timezone.utc).isoformat(),
    )


# ── correlate_event ───────────────────────────────────────────────────────────

def test_correlate_event_creates_new_incident_when_store_empty():
    event = _make_event()
    result = json.loads(correlate_event(event.model_dump_json(), "[]"))
    assert result["incident_id"]
    assert len(result["events"]) == 1
    assert result["status"] == IncidentStatus.OPEN.value


def test_correlate_event_appends_to_existing_incident():
    event1 = _make_event(identity="alice", source_type=LogSourceType.AWS)
    incident = _make_incident([event1])
    store = json.dumps([incident.model_dump()])

    event2 = _make_event(identity="alice", source_type=LogSourceType.AWS)
    result = json.loads(correlate_event(event2.model_dump_json(), store))

    assert result["incident_id"] == incident.incident_id
    assert len(result["events"]) == 2
    assert result["status"] == IncidentStatus.TRIAGING.value


def test_correlate_event_creates_new_when_different_actor():
    event1 = _make_event(identity="alice")
    incident = _make_incident([event1])
    store = json.dumps([incident.model_dump()])

    event2 = _make_event(identity="bob")
    result = json.loads(correlate_event(event2.model_dump_json(), store))

    assert result["incident_id"] != incident.incident_id
    assert len(result["events"]) == 1


def test_correlate_event_creates_new_when_different_source_type():
    event1 = _make_event(source_type=LogSourceType.AWS)
    incident = _make_incident([event1])
    store = json.dumps([incident.model_dump()])

    event2 = _make_event(source_type=LogSourceType.GCP)
    result = json.loads(correlate_event(event2.model_dump_json(), store))

    assert result["incident_id"] != incident.incident_id


def test_correlate_skips_closed_incidents():
    event1 = _make_event()
    incident = _make_incident([event1])
    closed = incident.model_copy(update={"status": IncidentStatus.CLOSED})
    store = json.dumps([closed.model_dump()])

    event2 = _make_event()
    result = json.loads(correlate_event(event2.model_dump_json(), store))

    assert result["incident_id"] != incident.incident_id


# ── score_incident ────────────────────────────────────────────────────────────

def test_score_incident_single_high_aws():
    event = _make_event(severity=AlertSeverity.HIGH, source_type=LogSourceType.AWS)
    incident = _make_incident([event])
    score = score_incident(incident.model_dump_json())
    assert score > 0
    # HIGH(7.0) * aws_weight(1.2) * recurrence_factor(1.0) = 8.4
    assert score == pytest.approx(8.4, abs=0.01)


def test_score_incident_critical_privileged_boost():
    event = _make_event(severity=AlertSeverity.CRITICAL, source_type=LogSourceType.AWS, is_privileged=True)
    incident = _make_incident([event])
    score = score_incident(incident.model_dump_json())
    # CRITICAL(10.0) * aws(1.2) * 1.0 recurrence * 1.5 privileged = 18.0
    assert score == pytest.approx(18.0, abs=0.01)


def test_score_incident_recurrence_increases_score():
    events = [_make_event() for _ in range(5)]
    incident = _make_incident(events)
    score = score_incident(incident.model_dump_json())
    single = score_incident(_make_incident([events[0]]).model_dump_json())
    assert score > single


def test_score_incident_recurrence_capped_at_3x():
    events = [_make_event() for _ in range(20)]
    incident = _make_incident(events)
    score = score_incident(incident.model_dump_json())
    # max recurrence_factor = 3.0; HIGH(7) * aws(1.2) * 3.0 = 25.2
    assert score <= 26.0  # with any small floating point tolerance


def test_score_empty_incident_returns_zero():
    incident = _make_incident([])
    score = score_incident(incident.model_dump_json())
    assert score == 0.0


# ── check_suppression ─────────────────────────────────────────────────────────

def test_check_suppression_low_score_suppressed():
    event = _make_event(severity=AlertSeverity.INFO)
    incident = _make_incident([event], score=0.5)
    rules = json.dumps({"min_priority_score": 2.0})
    result = json.loads(check_suppression(incident.model_dump_json(), rules))
    assert result["suppressed"] is True
    assert "priority_score" in result["reason"]


def test_check_suppression_known_good_identity():
    event = _make_event(identity="ci-bot@example.com")
    incident = _make_incident([event], score=10.0)
    rules = json.dumps({"min_priority_score": 1.0, "known_good_identities": ["ci-bot@example.com"]})
    result = json.loads(check_suppression(incident.model_dump_json(), rules))
    assert result["suppressed"] is True
    assert "known_good_identity" in result["reason"]


def test_check_suppression_info_only_low_recurrence():
    events = [_make_event(severity=AlertSeverity.INFO), _make_event(severity=AlertSeverity.INFO)]
    incident = _make_incident(events, score=5.0)
    result = json.loads(check_suppression(incident.model_dump_json(), "{}"))
    assert result["suppressed"] is True
    assert result["reason"] == "info_only_low_recurrence"


def test_check_suppression_not_suppressed():
    event = _make_event(severity=AlertSeverity.HIGH)
    incident = _make_incident([event], score=10.0)
    result = json.loads(check_suppression(incident.model_dump_json(), "{}"))
    assert result["suppressed"] is False
    assert result["reason"] == ""

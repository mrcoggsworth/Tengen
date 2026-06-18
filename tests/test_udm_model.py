"""UDM model: construction, defaults, enums, serialization."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from tengen.models.udm import (
    Metadata,
    Network,
    Noun,
    Resource,
    SecurityResult,
    UDMEvent,
    UDMEventType,
    UDMSecurityAction,
    UDMSeverity,
    User,
)


def test_udm_event_defaults():
    event = UDMEvent()
    assert event.metadata.event_type == UDMEventType.GENERIC_EVENT
    assert isinstance(event.principal, Noun)
    assert event.src is None
    assert event.security_result == []
    assert event.additional == {}


def test_noun_is_empty():
    assert Noun().is_empty()
    assert not Noun(hostname="host-1").is_empty()


def test_udm_event_full_construction_and_serialization():
    event = UDMEvent(
        metadata=Metadata(
            event_timestamp=datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc),
            event_type=UDMEventType.USER_RESOURCE_CREATION,
            product_event_type="CreateAccessKey",
            vendor_name="Amazon",
            product_name="AWS CloudTrail",
        ),
        principal=Noun(
            ip=["1.2.3.4"],
            user=User(userid="alice", email_addresses=["alice@example.com"]),
        ),
        target=Noun(resource=Resource(name="key-1", resource_type="AccessKey")),
        network=Network(ip_protocol="TCP", received_bytes=10),
        security_result=[
            SecurityResult(
                action=[UDMSecurityAction.ALLOW],
                severity=UDMSeverity.MEDIUM,
                summary="CreateAccessKey",
            )
        ],
        additional={"foo": "bar"},
    )
    data = json.loads(event.model_dump_json())
    assert data["metadata"]["event_type"] == "USER_RESOURCE_CREATION"
    assert data["principal"]["ip"] == ["1.2.3.4"]
    assert data["principal"]["user"]["userid"] == "alice"
    assert data["target"]["resource"]["resource_type"] == "AccessKey"
    assert data["security_result"][0]["action"] == ["ALLOW"]
    assert data["security_result"][0]["severity"] == "MEDIUM"
    assert data["additional"]["foo"] == "bar"

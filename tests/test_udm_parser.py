"""UDM parser + NormalizedEvent.to_udm projection."""
from __future__ import annotations

from tengen.models.normalized_event import LogSourceType
from tengen.models.udm import UDMEvent, UDMSeverity
from tengen.udm.field_registry import FieldRegistry
from tengen.udm.parser import UDMParser

CLOUDTRAIL_EVENT = {
    "eventVersion": "1.08",
    "eventSource": "iam.amazonaws.com",
    "eventName": "CreateAccessKey",
    "eventTime": "2024-01-15T10:30:00Z",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "1.2.3.4",
    "userAgent": "aws-cli/2.0",
    "userIdentity": {
        "type": "IAMUser",
        "userName": "alice",
        "arn": "arn:aws:iam::123456789:user/alice",
    },
    "requestParameters": {"userName": "bob"},
    "responseElements": {"accessKey": {"accessKeyId": "AKIA..."}},
    "errorCode": "",
}

CROWDSTRIKE_EVENT = {
    "event_type": "DetectionSummaryEvent",
    "DetectName": "Credential Theft",
    "MaxSeverity": 90,
    "Hostname": "WORKSTATION-01",
    "LocalIP": "192.168.1.100",
    "ExternalIP": "203.0.113.1",
    "CreatedTimestamp": "2024-01-15T10:30:00Z",
    "FalconHostLink": "https://falcon.crowdstrike.com/host",
    "Behaviors": [{"UserName": "jdoe", "Tactic": "Credential Access", "MD5": "abc123"}],
}


def test_parse_cloudtrail_to_udm():
    result = UDMParser().parse(CLOUDTRAIL_EVENT)
    udm = result.udm
    assert isinstance(udm, UDMEvent)
    assert udm.metadata.product_event_type == "CreateAccessKey"
    assert udm.metadata.vendor_name == "Amazon"
    assert udm.principal.ip == ["1.2.3.4"]
    assert udm.principal.user is not None
    assert "alice" in udm.principal.user.userid
    assert udm.security_result[0].severity == UDMSeverity.MEDIUM
    assert udm.metadata.event_timestamp is not None


def test_parse_discovers_unmapped_fields():
    result = UDMParser().parse(CLOUDTRAIL_EVENT)
    paths = {o.raw_path for o in result.unmapped}
    # These raw fields are not consumed by the AWS normalizer.
    assert "requestParameters.userName" in paths
    assert "responseElements.accessKey.accessKeyId" in paths
    # Consumed fields must NOT be reported as unmapped.
    assert "eventName" not in paths
    assert "sourceIPAddress" not in paths
    # Unmapped values are preserved on the UDM event.
    assert result.udm.additional["unmapped"]["requestParameters.userName"] == "bob"


def test_parse_records_to_registry(tmp_path):
    registry = FieldRegistry(db_path=str(tmp_path / "fields.db"))
    parser = UDMParser(registry=registry)
    parser.parse(CLOUDTRAIL_EVENT)
    rows = registry.list_fields()
    recorded = {r["raw_path"] for r in rows}
    assert "requestParameters.userName" in recorded
    # Suggestion heuristic routes a *userName field to the principal user id.
    row = next(r for r in rows if r["raw_path"] == "requestParameters.userName")
    assert row["suggested_udm_field"] == "principal.user.userid"
    registry.close()


def test_parse_crowdstrike_directional_ip_and_discovery(tmp_path):
    registry = FieldRegistry(db_path=str(tmp_path / "fields.db"))
    result = UDMParser(registry=registry).parse(CROWDSTRIKE_EVENT, LogSourceType.CROWDSTRIKE)
    # ExternalIP is consumed by the normalizer (dst); FalconHostLink/MD5 are new.
    paths = {o.raw_path for o in result.unmapped}
    assert "FalconHostLink" in paths
    assert "Behaviors[].MD5" in paths
    md5_obs = next(o for o in result.unmapped if o.raw_path == "Behaviors[].MD5")
    assert md5_obs.suggested_udm_field == "principal.file.md5"
    registry.close()


def test_discover_unmapped_excludes_consumed_only():
    parser = UDMParser()
    raw = {"eventSource": "iam.amazonaws.com", "eventVersion": "1.0", "eventName": "X"}
    obs = parser.discover_unmapped(raw, LogSourceType.AWS)
    assert obs == []

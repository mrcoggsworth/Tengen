"""Unit tests for the normalizer registry and per-source normalizers."""
from __future__ import annotations

import json
import pytest

from tengen.models.normalized_event import LogSourceType, NormalizedEvent, Outcome
from tengen.models.alert import AlertSeverity
from tengen.tools.normalizers.registry import detect_source_type, normalize


# ── Fixtures ──────────────────────────────────────────────────────────────────

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
    "errorMessage": "",
}

GCP_AUDIT_EVENT = {
    "logName": "projects/my-project/logs/cloudaudit.googleapis.com%2Factivity",
    "timestamp": "2024-01-15T10:30:00Z",
    "severity": "WARNING",
    "protoPayload": {
        "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "serviceName": "storage.googleapis.com",
        "methodName": "storage.buckets.delete",
        "resourceName": "projects/_/buckets/my-bucket",
        "authenticationInfo": {"principalEmail": "user@example.com"},
        "requestMetadata": {"callerIp": "5.6.7.8", "callerSuppliedUserAgent": "python"},
        "status": {"code": 0, "message": "OK"},
        "authorizationInfo": [{"permission": "storage.buckets.delete", "granted": True}],
    },
    "resource": {"type": "gcs_bucket", "labels": {"bucket_name": "my-bucket", "project_id": "my-project"}},
}

AZURE_EVENT = {
    "tenantId": "my-tenant-id",
    "operationName": {"value": "Microsoft.Compute/virtualMachines/delete"},
    "time": "2024-01-15T10:30:00Z",
    "caller": "admin@contoso.com",
    "status": {"value": "Succeeded"},
    "subscriptionId": "sub-123",
    "resourceId": "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-prod",
    "httpRequest": {"clientIpAddress": "9.10.11.12"},
}

CROWDSTRIKE_EVENT = {
    "event_type": "DetectionSummaryEvent",
    "DetectDescription": "Process inject detected",
    "MaxSeverity": 70,
    "Hostname": "WORKSTATION-01",
    "LocalIP": "192.168.1.100",
    "ExternalIP": "203.0.113.1",
    "CreatedTimestamp": "2024-01-15T10:30:00Z",
    "Behaviors": [
        {
            "UserName": "jdoe",
            "FileName": "injector.exe",
            "FilePath": "C:\\temp\\injector.exe",
            "CommandLine": "injector.exe --target lsass",
            "Tactic": "Credential Access",
            "Technique": "OS Credential Dumping",
        }
    ],
}

K8S_AUDIT_EVENT = {
    "apiVersion": "audit.k8s.io/v1",
    "kind": "Event",
    "level": "Request",
    "stage": "ResponseComplete",
    "verb": "list",
    "objectRef": {"resource": "secrets", "namespace": "production", "apiVersion": "v1"},
    "user": {"username": "system:serviceaccount:default:my-sa", "groups": ["system:serviceaccounts"]},
    "requestReceivedTimestamp": "2024-01-15T10:30:00Z",
    "responseStatus": {"code": 200},
    "sourceIPs": ["10.0.0.5"],
    "userAgent": "kubectl/v1.28.0",
}

FIREWALL_EVENT = {
    "action": "DENY",
    "src_ip": "1.1.1.1",
    "dst_ip": "10.0.0.1",
    "dst_port": 22,
    "protocol": "TCP",
    "timestamp": "2024-01-15T10:30:00Z",
}


# ── Detection tests ───────────────────────────────────────────────────────────

def test_detect_source_type_aws():
    assert detect_source_type(CLOUDTRAIL_EVENT) == LogSourceType.AWS

def test_detect_source_type_gcp():
    assert detect_source_type(GCP_AUDIT_EVENT) == LogSourceType.GCP

def test_detect_source_type_azure():
    assert detect_source_type(AZURE_EVENT) == LogSourceType.AZURE

def test_detect_source_type_crowdstrike():
    assert detect_source_type(CROWDSTRIKE_EVENT) == LogSourceType.CROWDSTRIKE

def test_detect_source_type_k8s():
    assert detect_source_type(K8S_AUDIT_EVENT) == LogSourceType.K8S

def test_detect_source_type_firewall():
    assert detect_source_type(FIREWALL_EVENT) == LogSourceType.FIREWALL

def test_detect_source_type_unknown():
    assert detect_source_type({"foo": "bar"}) == LogSourceType.UNKNOWN


# ── Normalization tests ───────────────────────────────────────────────────────

def test_normalize_cloudtrail_returns_normalized_event():
    event = normalize(CLOUDTRAIL_EVENT)
    assert isinstance(event, NormalizedEvent)
    assert event.source_type == LogSourceType.AWS
    # identity is the ARN (most precise AWS identifier)
    assert "alice" in event.actor.identity or event.actor.identity == "arn:aws:iam::123456789:user/alice"
    assert event.network.src_ip == "1.2.3.4"
    assert event.event_name == "CreateAccessKey"
    assert event.outcome == Outcome.SUCCESS

def test_normalize_gcp_returns_normalized_event():
    event = normalize(GCP_AUDIT_EVENT)
    assert isinstance(event, NormalizedEvent)
    assert event.source_type == LogSourceType.GCP
    assert event.actor.identity == "user@example.com"
    assert event.network.src_ip == "5.6.7.8"
    assert event.event_name == "storage.buckets.delete"

def test_normalize_azure_returns_normalized_event():
    event = normalize(AZURE_EVENT)
    assert isinstance(event, NormalizedEvent)
    assert event.source_type == LogSourceType.AZURE
    assert event.actor.identity == "admin@contoso.com"
    assert event.event_name == "Microsoft.Compute/virtualMachines/delete"

def test_normalize_crowdstrike_returns_normalized_event():
    event = normalize(CROWDSTRIKE_EVENT)
    assert isinstance(event, NormalizedEvent)
    assert event.source_type == LogSourceType.CROWDSTRIKE
    assert event.actor.identity == "jdoe"
    assert event.network.src_ip == "192.168.1.100"

def test_normalize_k8s_returns_normalized_event():
    event = normalize(K8S_AUDIT_EVENT)
    assert isinstance(event, NormalizedEvent)
    assert event.source_type in (LogSourceType.K8S, LogSourceType.OPENSHIFT)
    assert "secrets" in event.event_name.lower() or event.target.resource_type == "secrets"

def test_normalize_firewall_returns_normalized_event():
    event = normalize(FIREWALL_EVENT)
    assert isinstance(event, NormalizedEvent)
    assert event.source_type == LogSourceType.FIREWALL
    assert event.network.src_ip == "1.1.1.1"
    assert event.outcome == Outcome.FAILURE

def test_normalized_event_is_frozen():
    from pydantic import ValidationError
    event = normalize(CLOUDTRAIL_EVENT)
    with pytest.raises((ValidationError, TypeError, AttributeError)):
        event.__dict__["event_name"] = "mutated"  # type: ignore[index]
        # Pydantic v2 frozen models prevent attribute assignment
        event.event_name = "mutated"  # type: ignore[misc]

def test_normalized_event_serializes_to_json():
    event = normalize(CLOUDTRAIL_EVENT)
    data = json.loads(event.model_dump_json())
    assert data["source_type"] == "aws"
    assert "event_id" in data
    assert "timestamp" in data

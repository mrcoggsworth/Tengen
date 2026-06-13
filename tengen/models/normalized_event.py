from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from .alert import AlertSeverity
from .udm import (
    CloudContext,
    Metadata,
    Network,
    NetworkHttp,
    Noun,
    Resource,
    SecurityResult,
    UDMEvent,
    UDMEventType,
    UDMSecurityAction,
    UDMSeverity,
    User,
)


class LogSourceType(str, Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    CROWDSTRIKE = "crowdstrike"
    FIREWALL = "firewall"
    DDOS = "ddos"
    K8S = "k8s"
    OPENSHIFT = "openshift"
    UNKNOWN = "unknown"


class Outcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


# Maps Tengen source types onto UDM metadata.vendor_name / product_name and the
# UDM ``cloud.environment`` enum, so to_udm() emits Chronicle-recognisable values.
_SOURCE_TO_VENDOR: dict[str, tuple[str, str, str]] = {
    # source_type: (vendor_name, product_name, cloud_environment)
    "aws": ("Amazon", "AWS CloudTrail", "AMAZON_WEB_SERVICES"),
    "gcp": ("Google", "Google Cloud Audit Logs", "GOOGLE_CLOUD_PLATFORM"),
    "azure": ("Microsoft", "Azure Activity Logs", "MICROSOFT_AZURE"),
    "crowdstrike": ("CrowdStrike", "Falcon", ""),
    "firewall": ("Generic", "Firewall", ""),
    "ddos": ("Generic", "DDoS Detector", ""),
    "k8s": ("Kubernetes", "Kubernetes Audit", ""),
    "openshift": ("Red Hat", "OpenShift Audit", ""),
    "unknown": ("Unknown", "Unknown", ""),
}

_SEVERITY_TO_UDM: dict[AlertSeverity, UDMSeverity] = {
    AlertSeverity.CRITICAL: UDMSeverity.CRITICAL,
    AlertSeverity.HIGH: UDMSeverity.HIGH,
    AlertSeverity.MEDIUM: UDMSeverity.MEDIUM,
    AlertSeverity.LOW: UDMSeverity.LOW,
    AlertSeverity.INFO: UDMSeverity.INFORMATIONAL,
}


class ActorContext(BaseModel):
    """Who performed the action. Maps to UDM ``principal``."""

    identity: str = ""          # user ARN, email, service account, process
    identity_type: str = ""     # IAMUser, ServiceAccount, Root, Process, etc.
    account_id: str = ""        # AWS account, GCP project, Azure subscription
    is_privileged: bool = False

    model_config = {"frozen": True}


class TargetContext(BaseModel):
    """What was acted upon. Maps to UDM ``target``."""

    resource_name: str = ""
    resource_type: str = ""     # S3Bucket, GCS Bucket, VM, Pod, Namespace, etc.
    region: str = ""
    namespace: str = ""         # K8s namespace

    model_config = {"frozen": True}


class NetworkContext(BaseModel):
    """Network-layer details. Maps to UDM ``network`` + noun ip/port."""

    src_ip: str = ""
    dst_ip: str = ""
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = ""
    user_agent: str = ""
    bytes_in: int | None = None
    bytes_out: int | None = None

    model_config = {"frozen": True}


def _parse_timestamp(value: str) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


class NormalizedEvent(BaseModel):
    """Universal log event produced by every normalizer.

    Every source type maps its raw fields into this common schema before
    triage and routing. The raw_event is always preserved.

    This model is UDM-aligned: ``actor`` → ``principal``, ``target`` →
    ``target``, ``network`` → ``network`` + noun ip/port, ``outcome`` /
    ``severity`` → ``security_result``. Use :meth:`to_udm` to project a
    :class:`~tengen.models.udm.UDMEvent`. The ``vendor_name`` / ``product_name``
    / ``udm_event_type`` fields let a normalizer set explicit UDM metadata.
    """

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str
    source_type: LogSourceType
    log_type: str               # cloudtrail | gcp_audit | azure_activity | cs_detection | …
    actor: ActorContext = Field(default_factory=ActorContext)
    target: TargetContext = Field(default_factory=TargetContext)
    network: NetworkContext = Field(default_factory=NetworkContext)
    outcome: Outcome = Outcome.UNKNOWN
    event_name: str             # normalized action name
    severity: AlertSeverity = AlertSeverity.INFO
    raw_event: dict[str, Any]
    tags: list[str] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)

    # UDM-aligned metadata fields (optional; default-empty for back-compat).
    vendor_name: str = ""
    product_name: str = ""
    udm_event_type: UDMEventType | None = None

    model_config = {"frozen": True}

    # ── UDM projection ───────────────────────────────────────────────────────

    def to_udm(self) -> UDMEvent:
        """Project this normalized event onto a :class:`UDMEvent`."""
        vendor, product, cloud_env = _SOURCE_TO_VENDOR.get(
            self.source_type.value, ("Unknown", "Unknown", "")
        )

        metadata = Metadata(
            event_timestamp=_parse_timestamp(self.timestamp),
            event_type=self.udm_event_type or UDMEventType.GENERIC_EVENT,
            product_event_type=self.event_name,
            vendor_name=self.vendor_name or vendor,
            product_name=self.product_name or product,
            log_type=self.log_type,
            id=self.event_id,
        )

        # principal ← actor (+ source ip / port)
        principal = Noun(
            administrative_domain=self.actor.account_id,
            ip=[self.network.src_ip] if self.network.src_ip else [],
            port=self.network.src_port,
            labels={
                k: v
                for k, v in {
                    "identity_type": self.actor.identity_type,
                    "is_privileged": "true" if self.actor.is_privileged else "",
                }.items()
                if v
            },
        )
        if self.actor.identity:
            principal.user = User(
                userid=self.actor.identity,
                user_display_name=self.actor.identity,
                email_addresses=[self.actor.identity] if "@" in self.actor.identity else [],
            )
        if cloud_env:
            principal.cloud = CloudContext(
                environment=cloud_env, project_id=self.actor.account_id
            )

        # src ← source ip (network-level)
        src: Noun | None = None
        if self.network.src_ip:
            src = Noun(ip=[self.network.src_ip], port=self.network.src_port)

        # target ← target context (+ destination ip / port)
        target: Noun | None = None
        if any(
            (
                self.target.resource_name,
                self.target.resource_type,
                self.target.namespace,
                self.network.dst_ip,
            )
        ):
            target = Noun(
                namespace=self.target.namespace,
                ip=[self.network.dst_ip] if self.network.dst_ip else [],
                port=self.network.dst_port,
            )
            if self.target.resource_name or self.target.resource_type:
                target.resource = Resource(
                    name=self.target.resource_name,
                    resource_type=self.target.resource_type,
                )
            if cloud_env:
                target.cloud = CloudContext(environment=cloud_env)

        # network
        network: Network | None = None
        if any(
            (
                self.network.protocol,
                self.network.user_agent,
                self.network.bytes_in is not None,
                self.network.bytes_out is not None,
            )
        ):
            network = Network(
                ip_protocol=self.network.protocol,
                received_bytes=self.network.bytes_in,
                sent_bytes=self.network.bytes_out,
            )
            if self.network.user_agent:
                network.http = NetworkHttp(user_agent=self.network.user_agent)

        # security_result ← outcome + severity
        action = {
            Outcome.SUCCESS: UDMSecurityAction.ALLOW,
            Outcome.FAILURE: UDMSecurityAction.BLOCK,
        }.get(self.outcome, UDMSecurityAction.UNKNOWN_ACTION)
        security_result = SecurityResult(
            action=[action],
            severity=_SEVERITY_TO_UDM.get(self.severity, UDMSeverity.UNKNOWN_SEVERITY),
            summary=self.event_name,
            rule_labels={"outcome": self.outcome.value, **self.labels},
        )

        return UDMEvent(
            metadata=metadata,
            principal=principal,
            src=src,
            target=target,
            network=network,
            security_result=[security_result],
            additional={"tags": self.tags} if self.tags else {},
        )

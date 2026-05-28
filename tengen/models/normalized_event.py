from __future__ import annotations

import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from .alert import AlertSeverity


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


class ActorContext(BaseModel):
    """Who performed the action."""

    identity: str = ""          # user ARN, email, service account, process
    identity_type: str = ""     # IAMUser, ServiceAccount, Root, Process, etc.
    account_id: str = ""        # AWS account, GCP project, Azure subscription
    is_privileged: bool = False

    model_config = {"frozen": True}


class TargetContext(BaseModel):
    """What was acted upon."""

    resource_name: str = ""
    resource_type: str = ""     # S3Bucket, GCS Bucket, VM, Pod, Namespace, etc.
    region: str = ""
    namespace: str = ""         # K8s namespace

    model_config = {"frozen": True}


class NetworkContext(BaseModel):
    """Network-layer details."""

    src_ip: str = ""
    dst_ip: str = ""
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = ""
    user_agent: str = ""
    bytes_in: int | None = None
    bytes_out: int | None = None

    model_config = {"frozen": True}


class NormalizedEvent(BaseModel):
    """Universal log event produced by every normalizer.

    Every source type maps its raw fields into this common schema before
    triage and routing. The raw_event is always preserved.
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

    model_config = {"frozen": True}

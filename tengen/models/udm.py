"""Unified Data Model (UDM) — Tengen's canonical event schema.

Modeled on Google Chronicle / Google Security Operations' Unified Data Model
(https://cloud.google.com/chronicle/docs/event-processing/udm-overview).

The goal is a single, vendor-neutral shape that every incoming alert is parsed
into, so disparate terms like ``src_ip``, ``client-ip`` and ``sourceIPAddress``
all collapse onto ``principal.ip`` / ``src.ip``. Tengen does not aim to
reproduce *every* UDM field (there are hundreds); it implements the high-value
subset the harness routes and triages on, plus an ``additional`` escape hatch
that preserves anything not yet promoted to a first-class field.

New raw fields encountered by the parser that do not map onto this model are
recorded in the UDM field registry (see :mod:`tengen.udm.field_registry`) so
they can be reviewed and promoted into this model via a pull request.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ── Enums ───────────────────────────────────────────────────────────────────


class UDMEventType(str, Enum):
    """Subset of UDM ``metadata.event_type`` values.

    Mirrors the Chronicle enum names so downstream UDM consumers recognise them.
    Extend this enum (via the model-update PR flow) as new categories are needed.
    """

    GENERIC_EVENT = "GENERIC_EVENT"

    # Process
    PROCESS_LAUNCH = "PROCESS_LAUNCH"
    PROCESS_TERMINATION = "PROCESS_TERMINATION"
    PROCESS_INJECTION = "PROCESS_INJECTION"
    PROCESS_PRIVILEGE_ESCALATION = "PROCESS_PRIVILEGE_ESCALATION"
    PROCESS_MODULE_LOAD = "PROCESS_MODULE_LOAD"
    PROCESS_UNCATEGORIZED = "PROCESS_UNCATEGORIZED"

    # File
    FILE_CREATION = "FILE_CREATION"
    FILE_DELETION = "FILE_DELETION"
    FILE_MODIFICATION = "FILE_MODIFICATION"
    FILE_READ = "FILE_READ"
    FILE_OPEN = "FILE_OPEN"
    FILE_UNCATEGORIZED = "FILE_UNCATEGORIZED"

    # Registry / settings
    REGISTRY_CREATION = "REGISTRY_CREATION"
    REGISTRY_MODIFICATION = "REGISTRY_MODIFICATION"
    REGISTRY_DELETION = "REGISTRY_DELETION"
    SETTING_MODIFICATION = "SETTING_MODIFICATION"

    # User / identity
    USER_LOGIN = "USER_LOGIN"
    USER_LOGOUT = "USER_LOGOUT"
    USER_CREATION = "USER_CREATION"
    USER_DELETION = "USER_DELETION"
    USER_CHANGE_PASSWORD = "USER_CHANGE_PASSWORD"
    USER_CHANGE_PERMISSIONS = "USER_CHANGE_PERMISSIONS"
    USER_RESOURCE_ACCESS = "USER_RESOURCE_ACCESS"
    USER_RESOURCE_CREATION = "USER_RESOURCE_CREATION"
    USER_RESOURCE_DELETION = "USER_RESOURCE_DELETION"
    USER_RESOURCE_UPDATE_CONTENT = "USER_RESOURCE_UPDATE_CONTENT"
    USER_RESOURCE_UPDATE_PERMISSIONS = "USER_RESOURCE_UPDATE_PERMISSIONS"
    USER_UNCATEGORIZED = "USER_UNCATEGORIZED"

    # Network
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    NETWORK_FLOW = "NETWORK_FLOW"
    NETWORK_HTTP = "NETWORK_HTTP"
    NETWORK_DNS = "NETWORK_DNS"
    NETWORK_UNCATEGORIZED = "NETWORK_UNCATEGORIZED"

    # Cloud control-plane / resources
    RESOURCE_CREATION = "RESOURCE_CREATION"
    RESOURCE_DELETION = "RESOURCE_DELETION"
    RESOURCE_PERMISSIONS_CHANGE = "RESOURCE_PERMISSIONS_CHANGE"
    RESOURCE_READ = "RESOURCE_READ"
    RESOURCE_WRITTEN = "RESOURCE_WRITTEN"

    # Service
    SERVICE_CREATION = "SERVICE_CREATION"
    SERVICE_DELETION = "SERVICE_DELETION"
    SERVICE_MODIFICATION = "SERVICE_MODIFICATION"

    # Scans / status
    SCAN_HOST = "SCAN_HOST"
    SCAN_NETWORK = "SCAN_NETWORK"
    SCAN_UNCATEGORIZED = "SCAN_UNCATEGORIZED"
    STATUS_UPDATE = "STATUS_UPDATE"
    SYSTEM_AUDIT_LOG_WIPE = "SYSTEM_AUDIT_LOG_WIPE"


class UDMSeverity(str, Enum):
    """UDM ``security_result.severity`` levels."""

    UNKNOWN_SEVERITY = "UNKNOWN_SEVERITY"
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class UDMSecurityAction(str, Enum):
    """UDM ``security_result.action`` values."""

    UNKNOWN_ACTION = "UNKNOWN_ACTION"
    ALLOW = "ALLOW"
    ALLOW_WITH_MODIFICATION = "ALLOW_WITH_MODIFICATION"
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"
    FAIL = "FAIL"


class NetworkDirection(str, Enum):
    UNKNOWN_DIRECTION = "UNKNOWN_DIRECTION"
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"
    BROADCAST = "BROADCAST"


class Platform(str, Enum):
    UNKNOWN_PLATFORM = "UNKNOWN_PLATFORM"
    WINDOWS = "WINDOWS"
    MAC = "MAC"
    LINUX = "LINUX"


# ── Sub-nouns ─────────────────────────────────────────────────────────────────


class Location(BaseModel):
    name: str = ""
    city: str = ""
    state: str = ""
    country_or_region: str = ""


class User(BaseModel):
    """UDM ``Noun.user`` — an identity participating in the event."""

    userid: str = ""
    user_display_name: str = ""
    email_addresses: list[str] = Field(default_factory=list)
    windows_sid: str = ""
    product_object_id: str = ""
    group_identifiers: list[str] = Field(default_factory=list)
    attribute_roles: list[str] = Field(default_factory=list)


class File(BaseModel):
    full_path: str = ""
    file_type: str = ""
    mime_type: str = ""
    size: int | None = None
    md5: str = ""
    sha1: str = ""
    sha256: str = ""


class Process(BaseModel):
    pid: str = ""
    command_line: str = ""
    product_specific_process_id: str = ""
    parent_pid: str = ""
    file: File | None = None


class RegistryEntry(BaseModel):
    registry_key: str = ""
    registry_value_name: str = ""
    registry_value_data: str = ""


class Resource(BaseModel):
    """UDM ``Noun.resource`` — a (typically cloud) resource."""

    name: str = ""
    resource_type: str = ""
    resource_subtype: str = ""
    product_object_id: str = ""
    attribute_labels: dict[str, str] = Field(default_factory=dict)


class CloudContext(BaseModel):
    """UDM ``Noun.cloud`` — cloud environment context."""

    environment: str = ""          # GOOGLE_CLOUD_PLATFORM | AMAZON_WEB_SERVICES | MICROSOFT_AZURE
    project_id: str = ""
    availability_zone: str = ""


class Noun(BaseModel):
    """A participant/entity in a UDM event (principal, src, target, …).

    The same shape is reused for every UDM "noun". Fields are all optional so a
    noun only carries what the source provides.
    """

    hostname: str = ""
    asset_id: str = ""
    ip: list[str] = Field(default_factory=list)
    port: int | None = None
    mac: list[str] = Field(default_factory=list)
    administrative_domain: str = ""
    namespace: str = ""
    url: str = ""
    domain: str = ""
    email: str = ""
    application: str = ""
    platform: Platform = Platform.UNKNOWN_PLATFORM
    platform_version: str = ""
    user: User | None = None
    process: Process | None = None
    file: File | None = None
    registry: RegistryEntry | None = None
    resource: Resource | None = None
    cloud: CloudContext | None = None
    location: Location | None = None
    labels: dict[str, str] = Field(default_factory=dict)

    def is_empty(self) -> bool:
        """True when the noun carries no meaningful data."""
        data = self.model_dump(exclude_defaults=True)
        return not data


# ── Network ───────────────────────────────────────────────────────────────────


class NetworkHttp(BaseModel):
    method: str = ""
    user_agent: str = ""
    response_code: int | None = None
    referral_url: str = ""


class Network(BaseModel):
    ip_protocol: str = ""          # TCP | UDP | ICMP | …
    direction: NetworkDirection = NetworkDirection.UNKNOWN_DIRECTION
    application_protocol: str = ""  # HTTP | DNS | SSH | …
    session_id: str = ""
    sent_bytes: int | None = None
    received_bytes: int | None = None
    http: NetworkHttp | None = None


# ── Security result ─────────────────────────────────────────────────────────


class SecurityResult(BaseModel):
    """UDM ``security_result`` — a security product's classification/verdict."""

    action: list[UDMSecurityAction] = Field(default_factory=list)
    category: str = ""
    severity: UDMSeverity = UDMSeverity.UNKNOWN_SEVERITY
    severity_details: str = ""
    rule_name: str = ""
    rule_id: str = ""
    threat_name: str = ""
    description: str = ""
    summary: str = ""
    confidence: str = ""
    priority: str = ""
    alert_state: str = ""
    rule_labels: dict[str, str] = Field(default_factory=dict)


# ── Metadata ──────────────────────────────────────────────────────────────────


class Metadata(BaseModel):
    """UDM ``metadata`` — the who/what/when/where-from of the event."""

    event_timestamp: datetime | None = None
    collected_timestamp: datetime | None = None
    ingested_timestamp: datetime | None = None
    event_type: UDMEventType = UDMEventType.GENERIC_EVENT
    product_event_type: str = ""    # vendor's native event name (e.g. "AssumeRole")
    product_name: str = ""
    vendor_name: str = ""
    product_version: str = ""
    product_log_id: str = ""
    log_type: str = ""              # tengen log_type: cloudtrail | gcp_audit | …
    description: str = ""
    url_back_to_product: str = ""
    id: str = ""


# ── Top-level event ─────────────────────────────────────────────────────────


class UDMEvent(BaseModel):
    """A single Unified Data Model event.

    ``additional`` carries any source fields that are not yet represented as
    first-class UDM fields; the parser also records those paths in the field
    registry for review.
    """

    metadata: Metadata = Field(default_factory=Metadata)
    principal: Noun = Field(default_factory=Noun)
    src: Noun | None = None
    target: Noun | None = None
    intermediary: list[Noun] = Field(default_factory=list)
    observer: Noun | None = None
    about: list[Noun] = Field(default_factory=list)
    network: Network | None = None
    security_result: list[SecurityResult] = Field(default_factory=list)
    additional: dict[str, Any] = Field(default_factory=dict)

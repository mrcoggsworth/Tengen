"""Source field mappings and UDM-field suggestion heuristics.

``CONSUMED_PATHS`` records, per source type, the raw (dotted) field paths that
the existing normalizers already read and map into the UDM model. Any leaf path
in an incoming payload that is *not* in this set is a candidate "new field":
the parser records it in the field registry with a heuristic suggestion for
which UDM field it should map onto.

Dotted paths use ``[]`` to denote a list, so ``resources[].ARN`` matches the
``ARN`` key of every element of the ``resources`` list.
"""
from __future__ import annotations

from typing import Any

from tengen.models.normalized_event import LogSourceType

# Raw leaf paths each normalizer already consumes, keyed by source type.
CONSUMED_PATHS: dict[LogSourceType, set[str]] = {
    LogSourceType.AWS: {
        "eventID", "eventTime", "eventName", "eventVersion", "eventSource",
        "awsRegion", "sourceIPAddress", "userAgent", "errorCode",
        "userIdentity.arn", "userIdentity.accountId", "userIdentity.type",
        "userIdentity.userName",
        "resources[].ARN", "resources[].resourceName", "resources[].type",
    },
    LogSourceType.GCP: {
        "logName", "timestamp", "severity",
        "protoPayload.authenticationInfo.principalEmail",
        "protoPayload.requestMetadata.callerIp",
        "protoPayload.requestMetadata.callerSuppliedUserAgent",
        "protoPayload.resourceName", "protoPayload.methodName",
        "protoPayload.status.code",
        "resource.type", "resource.labels.project_id",
    },
    LogSourceType.AZURE: {
        "tenantId", "eventTimestamp", "time", "caller", "subscriptionId",
        "resourceId", "resourceProvider", "resourceProvider.value",
        "operationName", "operationName.value", "status", "status.value",
        "httpRequest.clientIpAddress", "level",
    },
    LogSourceType.CROWDSTRIKE: {
        "event_type", "CreatedTimestamp", "ProcessStartTime",
        "CustomerIdentifier", "DeviceDetails.Hostname", "Hostname",
        "LocalIP", "ExternalIP", "MaxSeverity", "DetectName",
        "Behaviors[].UserName", "Behaviors[].Technique", "Behaviors[].Tactic",
    },
    LogSourceType.K8S: {
        "apiVersion", "verb", "userAgent",
        "requestReceivedTimestamp", "stageTimestamp",
        "user.username", "objectRef.name", "objectRef.resource",
        "objectRef.namespace", "sourceIPs[]", "responseStatus.code",
    },
    LogSourceType.FIREWALL: {
        "timestamp", "time", "log_type", "src_ip", "dst_ip", "src_port",
        "dst_port", "protocol", "bytes_in", "bytes_out", "action", "interface",
    },
    LogSourceType.DDOS: {
        "timestamp", "start_time", "src_ip", "top_src_ip", "dst_ip",
        "target_ip", "dst_port", "protocol", "bytes_received", "attack_type",
        "attack_vector", "packets_per_second",
    },
}
# OpenShift audit logs share the Kubernetes shape.
CONSUMED_PATHS[LogSourceType.OPENSHIFT] = CONSUMED_PATHS[LogSourceType.K8S]


def flatten(data: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten a nested dict/list into ``{dotted_path: leaf_value}``.

    List indices collapse to ``[]`` so every element of a list shares one path.
    """
    out: dict[str, Any] = {}
    if isinstance(data, dict):
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            out.update(flatten(value, path))
    elif isinstance(data, list):
        path = f"{prefix}[]"
        for item in data:
            if isinstance(item, (dict, list)):
                out.update(flatten(item, path))
            else:
                # First scalar wins as the representative sample.
                out.setdefault(path, item)
    else:
        if prefix:
            out[prefix] = data
    return out


def _looks_like_ip(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parts = value.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return ":" in value and len(value) <= 45 and any(c in value for c in "abcdefABCDEF0123456789")


# (substring, suggested_udm_field) — first match wins, order matters.
_RULES: list[tuple[str, str]] = [
    ("useragent", "network.http.user_agent"),
    ("user_agent", "network.http.user_agent"),
    ("httpmethod", "network.http.method"),
    ("responsecode", "network.http.response_code"),
    ("statuscode", "network.http.response_code"),
    ("referer", "network.http.referral_url"),
    ("referral", "network.http.referral_url"),
    ("commandline", "principal.process.command_line"),
    ("command_line", "principal.process.command_line"),
    ("cmdline", "principal.process.command_line"),
    ("parentprocess", "principal.process.parent_pid"),
    ("processid", "principal.process.pid"),
    ("pid", "principal.process.pid"),
    ("process", "principal.process.command_line"),
    ("sha256", "principal.file.sha256"),
    ("sha1", "principal.file.sha1"),
    ("md5", "principal.file.md5"),
    ("filepath", "principal.file.full_path"),
    ("filename", "principal.file.full_path"),
    ("file", "principal.file.full_path"),
    ("registry", "principal.registry.registry_key"),
    ("hostname", "principal.hostname"),
    ("host", "principal.hostname"),
    ("computer", "principal.hostname"),
    ("device", "principal.hostname"),
    ("mac", "principal.mac"),
    ("namespace", "target.namespace"),
    ("emailaddress", "principal.user.email_addresses"),
    ("email", "principal.user.email_addresses"),
    ("username", "principal.user.userid"),
    ("userid", "principal.user.userid"),
    ("principal", "principal.user.userid"),
    ("caller", "principal.user.userid"),
    ("actor", "principal.user.userid"),
    ("subject", "principal.user.userid"),
    ("user", "principal.user.userid"),
    ("availabilityzone", "principal.cloud.availability_zone"),
    ("zone", "principal.cloud.availability_zone"),
    ("project", "principal.cloud.project_id"),
    ("subscription", "principal.cloud.project_id"),
    ("tenant", "principal.administrative_domain"),
    ("account", "principal.administrative_domain"),
    ("org", "principal.administrative_domain"),
    ("customer", "principal.administrative_domain"),
    ("country", "principal.location.country_or_region"),
    ("city", "principal.location.city"),
    ("region", "principal.location.name"),
    ("location", "principal.location.name"),
    ("bucket", "target.resource.name"),
    ("arn", "target.resource.name"),
    ("resourcetype", "target.resource.resource_type"),
    ("resource", "target.resource.name"),
    ("domain", "principal.domain"),
    ("url", "principal.url"),
    ("dstport", "target.port"),
    ("destport", "target.port"),
    ("srcport", "src.port"),
    ("sourceport", "src.port"),
    ("port", "target.port"),
    ("protocol", "network.ip_protocol"),
    ("proto", "network.ip_protocol"),
    ("bytesout", "network.sent_bytes"),
    ("bytessent", "network.sent_bytes"),
    ("bytesin", "network.received_bytes"),
    ("bytesreceived", "network.received_bytes"),
    ("bytes", "network.sent_bytes"),
    ("severity", "security_result.severity"),
    ("score", "security_result.severity"),
    ("threat", "security_result.threat_name"),
    ("signature", "security_result.rule_name"),
    ("rulename", "security_result.rule_name"),
    ("ruleid", "security_result.rule_id"),
    ("rule", "security_result.rule_name"),
    ("category", "security_result.category"),
    ("tactic", "security_result.category"),
    ("technique", "security_result.rule_name"),
    ("detection", "security_result.rule_name"),
    ("confidence", "security_result.confidence"),
    ("priority", "security_result.priority"),
    ("timestamp", "metadata.event_timestamp"),
    ("time", "metadata.event_timestamp"),
    ("date", "metadata.event_timestamp"),
    ("operationname", "metadata.product_event_type"),
    ("operation", "metadata.product_event_type"),
    ("methodname", "metadata.product_event_type"),
    ("eventname", "metadata.product_event_type"),
    ("action", "metadata.product_event_type"),
    ("verb", "metadata.product_event_type"),
    ("product", "metadata.product_name"),
    ("vendor", "metadata.vendor_name"),
]


def suggest_udm_field(raw_path: str, value: Any) -> str:
    """Heuristically suggest the UDM field a raw path should map onto.

    Returns a dotted UDM field path (e.g. ``principal.ip``) or ``""`` when no
    confident mapping is found (the field then lands in ``additional``).
    """
    leaf = raw_path.split(".")[-1].replace("[]", "").lower()
    direction_key = raw_path.lower()

    # IP fields are routed by direction (source vs destination).
    if "ip" in leaf and (_looks_like_ip(value) or leaf.endswith("ip") or "ipaddress" in leaf):
        if any(t in direction_key for t in ("dst", "dest", "target", "external", "remote", "destination")):
            return "target.ip"
        if any(t in direction_key for t in ("src", "source", "client", "caller", "local", "origin")):
            return "principal.ip"
        return "principal.ip"

    normalized = leaf.replace("_", "").replace("-", "")
    for token, field in _RULES:
        if token in normalized:
            return field
    return ""

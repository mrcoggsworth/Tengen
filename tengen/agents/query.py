"""QueryAgent — analyst-facing natural-language security query agent."""
from __future__ import annotations

import json

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

from ..config import settings


# ── CloudTrail ───────────────────────────────────────────────────────────────

def _query_cloudtrail(start_time: str, end_time: str, event_name: str = "", max_results: int = 50) -> str:
    """Query AWS CloudTrail events. start_time/end_time are ISO 8601 strings."""
    try:
        import boto3
        client = boto3.client("cloudtrail", region_name=settings.aws_region)
        kwargs: dict = {
            "StartTime": start_time,
            "EndTime": end_time,
            "MaxResults": max_results,
        }
        if event_name:
            kwargs["LookupAttributes"] = [{"AttributeKey": "EventName", "AttributeValue": event_name}]
        resp = client.lookup_events(**kwargs)
        return json.dumps(resp.get("Events", []))
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def _query_cloudtrail_by_ip(source_ip: str, start_time: str, end_time: str, max_results: int = 50) -> str:
    """Query CloudTrail events originating from a specific source IP."""
    try:
        import boto3
        client = boto3.client("cloudtrail", region_name=settings.aws_region)
        resp = client.lookup_events(
            LookupAttributes=[{"AttributeKey": "SourceIPAddress", "AttributeValue": source_ip}],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=max_results,
        )
        return json.dumps(resp.get("Events", []))
    except Exception as exc:
        return json.dumps({"error": str(exc)})


# ── GCP Audit ────────────────────────────────────────────────────────────────

def _query_gcp_audit(project_id: str, start_time: str, end_time: str,
                     principal_email: str = "", max_results: int = 50) -> str:
    """Query GCP Cloud Audit Logs for a project and time range."""
    try:
        from google.cloud import logging as gcp_logging
        client = gcp_logging.Client(project=project_id or settings.gcp_project_id)
        filter_parts = [
            'logName:"cloudaudit.googleapis.com"',
            f'timestamp>="{start_time}"',
            f'timestamp<="{end_time}"',
        ]
        if principal_email:
            filter_parts.append(f'protoPayload.authenticationInfo.principalEmail="{principal_email}"')
        entries = list(client.list_entries(filter_=" AND ".join(filter_parts), max_results=max_results))
        return json.dumps([dict(e) for e in entries], default=str)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


# ── Azure Activity ────────────────────────────────────────────────────────────

def _query_azure_activity(subscription_id: str, start_time: str, end_time: str,
                          caller: str = "", max_results: int = 50) -> str:
    """Query Azure Activity Logs for a subscription."""
    try:
        import httpx
        import os
        tenant_id = os.environ["AZURE_TENANT_ID"]
        client_id = os.environ["AZURE_CLIENT_ID"]
        client_secret = os.environ["AZURE_CLIENT_SECRET"]
        token_resp = httpx.post(
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
            data={"grant_type": "client_credentials", "client_id": client_id,
                  "client_secret": client_secret, "scope": "https://management.azure.com/.default"},
            timeout=10,
        )
        token_resp.raise_for_status()
        token = token_resp.json()["access_token"]
        filter_parts = [f"eventTimestamp ge '{start_time}'", f"eventTimestamp le '{end_time}'"]
        if caller:
            filter_parts.append(f"caller eq '{caller}'")
        resp = httpx.get(
            f"https://management.azure.com/subscriptions/{subscription_id}/providers/microsoft.insights/eventtypes/management/values",
            params={"api-version": "2015-04-01", "$filter": " and ".join(filter_parts), "$top": max_results},
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        resp.raise_for_status()
        return json.dumps(resp.json().get("value", []))
    except Exception as exc:
        return json.dumps({"error": str(exc)})


# ── CrowdStrike ───────────────────────────────────────────────────────────────

def _query_crowdstrike_detections(start_time: str, end_time: str,
                                  severity: str = "", max_results: int = 50) -> str:
    """Query CrowdStrike Falcon for detections in a time range."""
    try:
        import httpx
        import os
        base_url = os.environ.get("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com")
        token_resp = httpx.post(
            f"{base_url}/oauth2/token",
            data={"client_id": os.environ["CROWDSTRIKE_CLIENT_ID"],
                  "client_secret": os.environ["CROWDSTRIKE_CLIENT_SECRET"]},
            timeout=10,
        )
        token_resp.raise_for_status()
        token = token_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        fql = f"created_timestamp:>'{start_time}'+created_timestamp:<'{end_time}'"
        if severity:
            fql += f"+max_severity_displayname:'{severity}'"
        ids_resp = httpx.get(
            f"{base_url}/detects/queries/detects/v1",
            params={"filter": fql, "limit": max_results},
            headers=headers, timeout=15,
        )
        ids_resp.raise_for_status()
        ids = ids_resp.json().get("resources", [])
        if not ids:
            return "[]"
        detail_resp = httpx.post(
            f"{base_url}/detects/entities/summaries/GET/v1",
            json={"ids": ids}, headers=headers, timeout=15,
        )
        detail_resp.raise_for_status()
        return json.dumps(detail_resp.json().get("resources", []))
    except Exception as exc:
        return json.dumps({"error": str(exc)})


# ── Kubernetes ────────────────────────────────────────────────────────────────

def _query_k8s_events(namespace: str = "", resource_kind: str = "", max_results: int = 100) -> str:
    """Query Kubernetes cluster events, optionally filtered by namespace or resource kind."""
    try:
        import os
        from kubernetes import client, config  # type: ignore[import]
        try:
            config.load_incluster_config()
        except Exception:
            config.load_kube_config(config_file=os.environ.get("K8S_KUBECONFIG"))
        v1 = client.CoreV1Api()
        if namespace:
            events = v1.list_namespaced_event(namespace=namespace, limit=max_results)
        else:
            events = v1.list_event_for_all_namespaces(limit=max_results)
        results = [
            {"namespace": e.metadata.namespace, "reason": e.reason,
             "message": e.message, "type": e.type, "count": e.count,
             "involved_object": e.involved_object.name}
            for e in events.items
            if not resource_kind or e.involved_object.kind == resource_kind
        ]
        return json.dumps(results[:max_results])
    except Exception as exc:
        return json.dumps({"error": str(exc)})


# ── Cross-source correlation helper ──────────────────────────────────────────

def _correlate_ip_across_sources(ip_address: str, start_time: str, end_time: str) -> str:
    """Search for an IP address across all available sources and return a unified summary."""
    results: dict = {"ip": ip_address, "sources": {}}
    try:
        ct = _query_cloudtrail_by_ip(ip_address, start_time, end_time, max_results=10)
        ct_events = json.loads(ct)
        results["sources"]["cloudtrail"] = len(ct_events) if isinstance(ct_events, list) else ct_events
    except Exception as exc:
        results["sources"]["cloudtrail"] = str(exc)
    try:
        from ..tools.enrichment import lookup_ip_reputation, lookup_ip_geo
        results["sources"]["ip_reputation"] = json.loads(lookup_ip_reputation(ip_address))
        results["sources"]["ip_geo"] = json.loads(lookup_ip_geo(ip_address))
    except Exception as exc:
        results["sources"]["enrichment"] = str(exc)
    return json.dumps(results, indent=2)


query_agent = LlmAgent(
    name="query_agent",
    model=settings.model_name,
    description=(
        "Analyst-facing agent for ad-hoc natural-language security queries across "
        "CloudTrail, GCP Audit, Azure Activity, CrowdStrike, and Kubernetes. "
        "Supports cross-source IP correlation."
    ),
    instruction=(
        "You are the QueryAgent, a security analyst assistant. "
        "Translate natural-language security questions into targeted data queries. "
        "Available data sources and their tools: "
        "- AWS CloudTrail: query_cloudtrail (by time/event), query_cloudtrail_by_ip "
        "- GCP Audit: query_gcp_audit (by project/time/principal) "
        "- Azure Activity: query_azure_activity (by subscription/time/caller) "
        "- CrowdStrike: query_crowdstrike_detections (by time/severity) "
        "- Kubernetes: query_k8s_events (by namespace/resource) "
        "- Cross-source: correlate_ip_across_sources (find an IP everywhere) "
        "RESPONSE FORMAT: "
        "1. Brief summary of what was found (1-3 sentences). "
        "2. A markdown table of the most relevant results. "
        "3. Key observations or patterns. "
        "4. Recommended next actions if anything suspicious is found. "
        "If a query fails, explain why and suggest alternatives."
    ),
    tools=[
        FunctionTool(func=_query_cloudtrail),
        FunctionTool(func=_query_cloudtrail_by_ip),
        FunctionTool(func=_query_gcp_audit),
        FunctionTool(func=_query_azure_activity),
        FunctionTool(func=_query_crowdstrike_detections),
        FunctionTool(func=_query_k8s_events),
        FunctionTool(func=_correlate_ip_across_sources),
    ],
)

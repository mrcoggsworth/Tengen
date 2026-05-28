"""Enrichment tools: field extraction + external threat intel lookups."""
from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


# ── Legacy field-extraction enrichers ──────────────────────────────────────

def enrich_cloudtrail_alert(alert: Any) -> dict:
    event = alert.raw_event if hasattr(alert, "raw_event") else {}
    return {
        "user_agent": event.get("userAgent", ""),
        "source_ip": event.get("sourceIPAddress", ""),
        "user_identity_type": event.get("userIdentity", {}).get("type", ""),
        "user_arn": event.get("userIdentity", {}).get("arn", ""),
        "error_code": event.get("errorCode", ""),
        "error_message": event.get("errorMessage", ""),
        "request_parameters": event.get("requestParameters", {}),
    }


def enrich_gcp_audit_alert(alert: Any) -> dict:
    payload = (alert.raw_event if hasattr(alert, "raw_event") else {}).get("protoPayload", {})
    return {
        "caller_ip": payload.get("requestMetadata", {}).get("callerIp", ""),
        "caller_user_agent": payload.get("requestMetadata", {}).get("callerSuppliedUserAgent", ""),
        "principal_email": payload.get("authenticationInfo", {}).get("principalEmail", ""),
        "service_name": payload.get("serviceName", ""),
        "resource_name": payload.get("resourceName", ""),
        "authorization_info": payload.get("authorizationInfo", []),
    }


# ── External threat intelligence lookups ──────────────────────────────────

def lookup_ip_reputation(ip: str) -> str:
    """Check IP reputation via AbuseIPDB (falls back to VirusTotal).

    Returns JSON: {ip, abuse_score, country, isp, total_reports, is_tor, source}
    Requires ABUSE_IPDB_KEY or VT_API_KEY env var.
    """
    try:
        import httpx
        key = os.environ.get("ABUSE_IPDB_KEY", "")
        if key:
            resp = httpx.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                headers={"Key": key, "Accept": "application/json"},
                timeout=8,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return json.dumps({
                "ip": ip,
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", ""),
                "isp": data.get("isp", ""),
                "total_reports": data.get("totalReports", 0),
                "is_tor": data.get("isTor", False),
                "source": "abuseipdb",
            })

        vt_key = os.environ.get("VT_API_KEY", "")
        if vt_key:
            resp = httpx.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": vt_key},
                timeout=8,
            )
            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return json.dumps({
                "ip": ip,
                "abuse_score": int(stats.get("malicious", 0) / max(sum(stats.values()), 1) * 100),
                "country": attrs.get("country", ""),
                "isp": attrs.get("as_owner", ""),
                "total_reports": stats.get("malicious", 0),
                "is_tor": False,
                "source": "virustotal",
            })

        return json.dumps({"ip": ip, "error": "no API key configured", "source": "none"})
    except Exception as exc:
        logger.error("lookup_ip_reputation failed for %s: %s", ip, exc)
        return json.dumps({"ip": ip, "error": str(exc)})


def lookup_ip_geo(ip: str) -> str:
    """Geolocate an IP via ipinfo.io.

    Returns JSON: {ip, city, region, country, org, timezone, loc}
    Requires IPINFO_TOKEN env var (optional — free tier works without).
    """
    try:
        import httpx
        token = os.environ.get("IPINFO_TOKEN", "")
        url = f"https://ipinfo.io/{ip}/json"
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        resp = httpx.get(url, headers=headers, timeout=8)
        resp.raise_for_status()
        data = resp.json()
        return json.dumps({
            "ip": ip,
            "city": data.get("city", ""),
            "region": data.get("region", ""),
            "country": data.get("country", ""),
            "org": data.get("org", ""),
            "timezone": data.get("timezone", ""),
            "loc": data.get("loc", ""),
        })
    except Exception as exc:
        logger.error("lookup_ip_geo failed for %s: %s", ip, exc)
        return json.dumps({"ip": ip, "error": str(exc)})


def lookup_domain(domain: str) -> str:
    """Look up domain registration and passive DNS context.

    Returns JSON: {domain, registrar, created, expires, name_servers, categories}
    Requires SECURITYTRAILS_API_KEY env var.
    """
    try:
        import httpx
        key = os.environ.get("SECURITYTRAILS_API_KEY", "")
        if key:
            resp = httpx.get(
                f"https://api.securitytrails.com/v1/domain/{domain}",
                headers={"APIKEY": key, "Accept": "application/json"},
                timeout=8,
            )
            resp.raise_for_status()
            data = resp.json()
            alexa = data.get("alexa_rank")
            return json.dumps({
                "domain": domain,
                "registrar": data.get("registrar", ""),
                "created": data.get("created", ""),
                "expires": data.get("expires", ""),
                "name_servers": data.get("current_dns", {}).get("ns", {}).get("values", []),
                "categories": data.get("tags", []),
                "alexa_rank": alexa,
                "source": "securitytrails",
            })
        return json.dumps({"domain": domain, "error": "SECURITYTRAILS_API_KEY not set"})
    except Exception as exc:
        logger.error("lookup_domain failed for %s: %s", domain, exc)
        return json.dumps({"domain": domain, "error": str(exc)})


def lookup_file_hash(sha256: str) -> str:
    """Look up a file hash on VirusTotal.

    Returns JSON: {sha256, malicious, suspicious, harmless, undetected, names, tags}
    Requires VT_API_KEY env var.
    """
    try:
        import httpx
        key = os.environ.get("VT_API_KEY", "")
        if not key:
            return json.dumps({"sha256": sha256, "error": "VT_API_KEY not set"})
        resp = httpx.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": key},
            timeout=10,
        )
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return json.dumps({
            "sha256": sha256,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "names": attrs.get("names", [])[:5],
            "tags": attrs.get("tags", []),
            "type_description": attrs.get("type_description", ""),
            "source": "virustotal",
        })
    except Exception as exc:
        logger.error("lookup_file_hash failed for %s: %s", sha256, exc)
        return json.dumps({"sha256": sha256, "error": str(exc)})


def lookup_user_context(identifier: str) -> str:
    """Fetch user context from Okta or Azure Graph.

    identifier: email address or UPN.
    Returns JSON: {id, email, display_name, department, title, manager, mfa_enrolled,
                   last_login, account_enabled, groups, source}
    Requires OKTA_API_TOKEN + OKTA_DOMAIN, or AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET.
    """
    try:
        import httpx

        okta_token = os.environ.get("OKTA_API_TOKEN", "")
        okta_domain = os.environ.get("OKTA_DOMAIN", "")
        if okta_token and okta_domain:
            resp = httpx.get(
                f"https://{okta_domain}/api/v1/users/{identifier}",
                headers={"Authorization": f"SSWS {okta_token}", "Accept": "application/json"},
                timeout=8,
            )
            resp.raise_for_status()
            user = resp.json()
            profile = user.get("profile", {})
            return json.dumps({
                "id": user.get("id", ""),
                "email": profile.get("email", ""),
                "display_name": f"{profile.get('firstName','')} {profile.get('lastName','')}".strip(),
                "department": profile.get("department", ""),
                "title": profile.get("title", ""),
                "manager": profile.get("manager", ""),
                "mfa_enrolled": user.get("credentials", {}).get("factors") is not None,
                "last_login": user.get("lastLogin", ""),
                "account_enabled": user.get("status") == "ACTIVE",
                "groups": [],
                "source": "okta",
            })

        tenant_id = os.environ.get("AZURE_TENANT_ID", "")
        client_id = os.environ.get("AZURE_CLIENT_ID", "")
        client_secret = os.environ.get("AZURE_CLIENT_SECRET", "")
        if tenant_id and client_id and client_secret:
            token_resp = httpx.post(
                f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                data={"grant_type": "client_credentials", "client_id": client_id,
                      "client_secret": client_secret, "scope": "https://graph.microsoft.com/.default"},
                timeout=10,
            )
            token_resp.raise_for_status()
            token = token_resp.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            user_resp = httpx.get(
                f"https://graph.microsoft.com/v1.0/users/{identifier}"
                "?$select=id,displayName,mail,department,jobTitle,accountEnabled,signInActivity",
                headers=headers, timeout=8,
            )
            user_resp.raise_for_status()
            u = user_resp.json()
            return json.dumps({
                "id": u.get("id", ""),
                "email": u.get("mail", ""),
                "display_name": u.get("displayName", ""),
                "department": u.get("department", ""),
                "title": u.get("jobTitle", ""),
                "manager": "",
                "mfa_enrolled": None,
                "last_login": u.get("signInActivity", {}).get("lastSignInDateTime", ""),
                "account_enabled": u.get("accountEnabled", True),
                "groups": [],
                "source": "azure_graph",
            })

        return json.dumps({"identifier": identifier, "error": "no identity provider configured"})
    except Exception as exc:
        logger.error("lookup_user_context failed for %s: %s", identifier, exc)
        return json.dumps({"identifier": identifier, "error": str(exc)})


def lookup_asset_context(asset_id: str) -> str:
    """Look up asset/resource context from CMDB, AWS Config, or GCP Asset Inventory.

    asset_id: AWS ARN, GCP resource name, or CMDB asset ID.
    Returns JSON: {asset_id, name, type, owner, env, tags, compliance_violations, source}
    Requires CMDB_ENDPOINT or standard AWS/GCP credentials.
    """
    try:
        import httpx

        cmdb_endpoint = os.environ.get("CMDB_ENDPOINT", "")
        cmdb_token = os.environ.get("CMDB_TOKEN", "")
        if cmdb_endpoint:
            headers = {"Authorization": f"Bearer {cmdb_token}"} if cmdb_token else {}
            resp = httpx.get(
                f"{cmdb_endpoint}/assets/{asset_id}",
                headers=headers,
                timeout=8,
            )
            resp.raise_for_status()
            data = resp.json()
            return json.dumps({
                "asset_id": asset_id,
                "name": data.get("name", ""),
                "type": data.get("type", ""),
                "owner": data.get("owner", ""),
                "env": data.get("environment", ""),
                "tags": data.get("tags", {}),
                "compliance_violations": data.get("compliance_violations", []),
                "source": "cmdb",
            })

        if asset_id.startswith("arn:"):
            import boto3
            config = boto3.client("config")
            resp = config.get_resource_config_history(
                resourceType="AWS::IAM::User",  # caller should pass correct type; best-effort
                resourceId=asset_id.split("/")[-1],
                limit=1,
            )
            items = resp.get("configurationItems", [])
            if items:
                item = items[0]
                return json.dumps({
                    "asset_id": asset_id,
                    "name": item.get("resourceName", ""),
                    "type": item.get("resourceType", ""),
                    "owner": "",
                    "env": item.get("tags", {}).get("Environment", ""),
                    "tags": item.get("tags", {}),
                    "compliance_violations": [],
                    "source": "aws_config",
                })

        return json.dumps({"asset_id": asset_id, "error": "no asset source configured"})
    except Exception as exc:
        logger.error("lookup_asset_context failed for %s: %s", asset_id, exc)
        return json.dumps({"asset_id": asset_id, "error": str(exc)})

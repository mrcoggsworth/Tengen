"""GCP containment actions."""
from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)


def disable_service_account(finding_json: str, service_account_email: str, project_id: str) -> str:
    try:
        from google.oauth2 import service_account
        import googleapiclient.discovery
        service = googleapiclient.discovery.build("iam", "v1")
        name = f"projects/{project_id}/serviceAccounts/{service_account_email}"
        service.projects().serviceAccounts().disable(name=name).execute()
        logger.info("Disabled GCP service account %s", service_account_email)
        return json.dumps({"action": "disable_service_account", "status": "success", "sa": service_account_email})
    except Exception as exc:
        logger.error("disable_service_account failed: %s", exc)
        return json.dumps({"action": "disable_service_account", "status": "error", "error": str(exc)})


def add_vpc_firewall_deny(finding_json: str, project_id: str, source_ip: str, network: str = "default") -> str:
    try:
        import googleapiclient.discovery
        service = googleapiclient.discovery.build("compute", "v1")
        rule = {
            "name": f"tengen-block-{source_ip.replace('.', '-')}",
            "description": "Tengen automated containment block",
            "network": f"projects/{project_id}/global/networks/{network}",
            "priority": 900,
            "direction": "INGRESS",
            "denied": [{"IPProtocol": "all"}],
            "sourceRanges": [f"{source_ip}/32"],
        }
        service.firewalls().insert(project=project_id, body=rule).execute()
        logger.info("Added GCP firewall deny rule for IP %s", source_ip)
        return json.dumps({"action": "add_vpc_firewall_deny", "status": "success", "ip": source_ip})
    except Exception as exc:
        logger.error("add_vpc_firewall_deny failed: %s", exc)
        return json.dumps({"action": "add_vpc_firewall_deny", "status": "error", "error": str(exc)})

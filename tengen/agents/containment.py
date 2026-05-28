"""ContainmentAgent — executes cloud containment actions based on Finding severity."""
from __future__ import annotations

import json

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

from ..config import settings

# ── AWS ─────────────────────────────────────────────────────────────────────

def _disable_iam_access_key(finding_json: str, access_key_id: str) -> str:
    """Disable an AWS IAM access key. Use for compromised credentials."""
    from ..tools.containment.aws_containment import disable_iam_access_key
    return disable_iam_access_key(finding_json, access_key_id)


def _revoke_sts_sessions(finding_json: str, username: str) -> str:
    """Attach a DenyAll policy to an IAM user to terminate active STS sessions."""
    from ..tools.containment.aws_containment import revoke_sts_sessions
    return revoke_sts_sessions(finding_json, username)


def _modify_security_group_deny(finding_json: str, group_id: str, source_ip: str) -> str:
    """Revoke ingress rules from an EC2 security group to block a malicious IP."""
    from ..tools.containment.aws_containment import modify_security_group_deny
    return modify_security_group_deny(finding_json, group_id, source_ip)


def _disable_iam_user(finding_json: str, username: str) -> str:
    """Disable all access keys for an AWS IAM user."""
    from ..tools.containment.aws_containment import disable_iam_user
    return disable_iam_user(finding_json, username)


# ── GCP ─────────────────────────────────────────────────────────────────────

def _disable_gcp_service_account(finding_json: str, service_account_email: str, project_id: str) -> str:
    """Disable a GCP service account to stop unauthorized API calls."""
    from ..tools.containment.gcp_containment import disable_service_account
    return disable_service_account(finding_json, service_account_email, project_id)


def _add_gcp_firewall_deny(finding_json: str, project_id: str, source_ip: str, network: str = "default") -> str:
    """Add a VPC firewall rule to block ingress from a malicious source IP."""
    from ..tools.containment.gcp_containment import add_vpc_firewall_deny
    return add_vpc_firewall_deny(finding_json, project_id, source_ip, network)


# ── Azure ────────────────────────────────────────────────────────────────────

def _disable_azure_ad_user(finding_json: str, user_id: str) -> str:
    """Disable an Azure AD user account via Microsoft Graph API."""
    from ..tools.containment.azure_containment import disable_azure_ad_user
    return disable_azure_ad_user(finding_json, user_id)


def _revoke_azure_refresh_tokens(finding_json: str, user_id: str) -> str:
    """Revoke all Azure AD refresh tokens for a user, forcing re-authentication."""
    from ..tools.containment.azure_containment import revoke_azure_refresh_tokens
    return revoke_azure_refresh_tokens(finding_json, user_id)


# ── Kubernetes ───────────────────────────────────────────────────────────────

def _cordon_k8s_node(finding_json: str, node_name: str) -> str:
    """Cordon a Kubernetes node to prevent new pod scheduling."""
    from ..tools.containment.k8s_containment import cordon_node
    return cordon_node(finding_json, node_name)


def _delete_k8s_pod(finding_json: str, namespace: str, pod_name: str) -> str:
    """Delete a Kubernetes pod immediately."""
    from ..tools.containment.k8s_containment import delete_pod
    return delete_pod(finding_json, namespace, pod_name)


def _delete_k8s_service_account_token(finding_json: str, namespace: str, secret_name: str) -> str:
    """Delete a Kubernetes service account token secret."""
    from ..tools.containment.k8s_containment import delete_service_account_token
    return delete_service_account_token(finding_json, namespace, secret_name)


def _create_k8s_network_policy_deny(finding_json: str, namespace: str, label_selector_json: str) -> str:
    """Create a Kubernetes NetworkPolicy that denies all ingress/egress for matching pods."""
    from ..tools.containment.k8s_containment import create_network_policy_deny
    label_selector = json.loads(label_selector_json)
    return create_network_policy_deny(finding_json, namespace, label_selector)


containment_agent = LlmAgent(
    name="containment_agent",
    model=settings.model_name,
    description=(
        "Executes real containment actions against AWS, GCP, Azure, and Kubernetes "
        "resources based on Finding severity. CRITICAL/HIGH → auto-execute. "
        "MEDIUM → flag for analyst. LOW/INFO → skip."
    ),
    instruction=(
        "You are the ContainmentAgent. You receive a Finding JSON with a severity field. "
        "RULES: "
        "- severity=CRITICAL or HIGH: execute the most appropriate containment action(s) immediately. "
        "- severity=MEDIUM: do NOT execute. Return JSON: "
        '  {"action": "pending_analyst_approval", "finding_id": "<id>", "recommended_actions": [...]}. '
        "- severity=LOW or INFO: return JSON: "
        '  {"action": "skipped", "reason": "severity too low"}. '
        "CONTAINMENT SELECTION GUIDE: "
        "- AWS compromised key → disable_iam_access_key, then revoke_sts_sessions "
        "- AWS compromised user → disable_iam_user "
        "- AWS network threat → modify_security_group_deny "
        "- GCP compromised SA → disable_gcp_service_account "
        "- GCP network threat → add_gcp_firewall_deny "
        "- Azure compromised user → disable_azure_ad_user + revoke_azure_refresh_tokens "
        "- K8s compromised pod → delete_k8s_pod + create_k8s_network_policy_deny "
        "- K8s compromised node → cordon_k8s_node "
        "- K8s stolen token → delete_k8s_service_account_token "
        "After each action, record the tool result. "
        "Return final JSON: {finding_id, severity, actions_taken: [{action, status, details}]}."
    ),
    tools=[
        FunctionTool(func=_disable_iam_access_key),
        FunctionTool(func=_revoke_sts_sessions),
        FunctionTool(func=_modify_security_group_deny),
        FunctionTool(func=_disable_iam_user),
        FunctionTool(func=_disable_gcp_service_account),
        FunctionTool(func=_add_gcp_firewall_deny),
        FunctionTool(func=_disable_azure_ad_user),
        FunctionTool(func=_revoke_azure_refresh_tokens),
        FunctionTool(func=_cordon_k8s_node),
        FunctionTool(func=_delete_k8s_pod),
        FunctionTool(func=_delete_k8s_service_account_token),
        FunctionTool(func=_create_k8s_network_policy_deny),
    ],
)

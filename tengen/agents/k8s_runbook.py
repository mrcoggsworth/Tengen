"""K8sRunbookAgent — investigates Kubernetes audit log security events."""
from __future__ import annotations

import json

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

from ..config import settings
from ..tools.runbook_loader import list_runbooks, load_runbook


def _list_k8s_runbooks() -> str:
    """List all available Kubernetes runbooks."""
    runbooks = list_runbooks("k8s")
    return ", ".join(runbooks) if runbooks else "no runbooks found"


def _load_k8s_runbook(event_type: str) -> str:
    """Load a specific Kubernetes runbook by event type slug."""
    runbook = load_runbook("k8s", event_type)
    if runbook is None:
        return f"no runbook found for event_type={event_type}"
    return runbook.model_dump_json()


def _enrich_k8s_event(normalized_event_json: str) -> str:
    """Extract key security context from a normalized Kubernetes audit event."""
    try:
        event = json.loads(normalized_event_json)
        raw = event.get("raw_event", {})
        obj_ref = raw.get("objectRef", {})
        user = raw.get("user", {})
        return json.dumps({
            "user": user.get("username", event.get("actor", {}).get("identity", "")),
            "user_groups": user.get("groups", []),
            "verb": raw.get("verb", ""),
            "resource": obj_ref.get("resource", event.get("target", {}).get("resource_type", "")),
            "resource_name": obj_ref.get("name", event.get("target", {}).get("resource_id", "")),
            "namespace": obj_ref.get("namespace", event.get("target", {}).get("namespace", "")),
            "api_group": obj_ref.get("apiGroup", ""),
            "source_ip": event.get("network", {}).get("src_ip", raw.get("sourceIPs", [""])[0]),
            "user_agent": raw.get("userAgent", ""),
            "response_code": raw.get("responseStatus", {}).get("code", 0),
            "stage": raw.get("stage", ""),
            "is_service_account": "system:serviceaccount" in user.get("username", ""),
            "tags": event.get("tags", []),
        })
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def _classify_k8s_threat(normalized_event_json: str) -> str:
    """Classify the Kubernetes event into a threat category.

    Returns: 'privileged_container', 'secrets_access', 'anomalous_exec', or 'unknown'.
    """
    try:
        event = json.loads(normalized_event_json)
        raw = event.get("raw_event", {})
        tags = [t.lower() for t in event.get("tags", [])]
        verb = raw.get("verb", "").lower()
        obj_ref = raw.get("objectRef", {})
        resource = obj_ref.get("resource", "").lower()
        subresource = obj_ref.get("subresource", "").lower()

        if subresource in ("exec", "attach") or "exec" in tags:
            return "anomalous_exec"
        if resource == "secrets" and verb in ("get", "list", "watch"):
            return "secrets_access"
        if "privileged" in tags or "privileged_container" in tags:
            return "privileged_container"
        if resource == "pods" and verb == "create":
            req_body = raw.get("requestObject", {}).get("spec", {})
            for container in req_body.get("containers", []) + req_body.get("initContainers", []):
                sc = container.get("securityContext", {})
                if sc.get("privileged") or sc.get("runAsUser") == 0:
                    return "privileged_container"
        return "unknown"
    except Exception:
        return "unknown"


k8s_runbook_agent = LlmAgent(
    name="k8s_runbook_agent",
    model=settings.model_name,
    description="Investigates Kubernetes API server audit log security events.",
    instruction=(
        "You are the K8sRunbookAgent. You receive a normalized Kubernetes audit event as JSON. "
        "1. Call enrich_k8s_event to extract user, verb, resource, namespace, and IP context. "
        "2. Call classify_k8s_threat to determine the threat category. "
        "3. List available runbooks with list_k8s_runbooks. "
        "4. Load the best matching runbook with load_k8s_runbook "
        "   (try: privileged_container, secrets_access, anomalous_exec). "
        "5. Walk through each runbook step with the enriched context. "
        "6. Produce a JSON Finding: "
        "   {finding_id, alert_id, source='k8s', severity, title, description, "
        "    remediation_steps, enrichment: {user, verb, resource, namespace, src_ip}}. "
        "Treat exec/attach on privileged pods and bulk secrets reads as HIGH severity. "
        "Return only the Finding JSON."
    ),
    tools=[
        FunctionTool(func=_list_k8s_runbooks),
        FunctionTool(func=_load_k8s_runbook),
        FunctionTool(func=_enrich_k8s_event),
        FunctionTool(func=_classify_k8s_threat),
    ],
)

"""EDRRunbookAgent — investigates CrowdStrike EDR detections."""
from __future__ import annotations

import json

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

from ..config import settings
from ..tools.runbook_loader import list_runbooks, load_runbook


def _list_edr_runbooks() -> str:
    """List all available EDR runbooks."""
    runbooks = list_runbooks("edr")
    return ", ".join(runbooks) if runbooks else "no runbooks found"


def _load_edr_runbook(event_type: str) -> str:
    """Load a specific EDR runbook by event type slug."""
    runbook = load_runbook("edr", event_type)
    if runbook is None:
        return f"no runbook found for event_type={event_type}"
    return runbook.model_dump_json()


def _enrich_crowdstrike_event(normalized_event_json: str) -> str:
    """Extract key threat indicators from a normalized CrowdStrike event."""
    try:
        event = json.loads(normalized_event_json)
        raw = event.get("raw_event", {})
        behaviors = raw.get("behaviors", raw.get("Behaviors", []))
        tactics = list({b.get("tactic", b.get("Tactic", "")) for b in behaviors if b.get("tactic") or b.get("Tactic")})
        techniques = list({b.get("technique", b.get("Technique", "")) for b in behaviors if b.get("technique") or b.get("Technique")})
        filenames = [b.get("filename", b.get("FileName", "")) for b in behaviors if b.get("filename") or b.get("FileName")]
        cmdlines = [b.get("cmdline", b.get("CommandLine", "")) for b in behaviors if b.get("cmdline") or b.get("CommandLine")]
        sha256s = list({b.get("sha256", b.get("SHA256HashData", "")) for b in behaviors if b.get("sha256") or b.get("SHA256HashData")})
        return json.dumps({
            "device_hostname": raw.get("device", {}).get("hostname", event.get("target", {}).get("hostname", "")),
            "device_os": raw.get("device", {}).get("platform_name", ""),
            "agent_id": raw.get("device", {}).get("device_id", ""),
            "detection_id": raw.get("detection_id", raw.get("DetectionId", "")),
            "severity": raw.get("max_severity_displayname", event.get("severity", "")),
            "tactics": tactics,
            "techniques": techniques,
            "filenames": filenames[:5],
            "cmdlines": cmdlines[:5],
            "sha256_hashes": sha256s,
            "src_ip": event.get("network", {}).get("src_ip", ""),
            "tags": event.get("tags", []),
        })
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def _classify_threat_type(normalized_event_json: str) -> str:
    """Classify the EDR detection into a threat category for runbook selection.

    Returns: 'malware_detection', 'lateral_movement', 'credential_dumping', or 'unknown'.
    """
    try:
        event = json.loads(normalized_event_json)
        raw = event.get("raw_event", {})
        tags = [t.lower() for t in event.get("tags", [])]
        behaviors = raw.get("behaviors", raw.get("Behaviors", []))
        tactics = [b.get("tactic", b.get("Tactic", "")).lower() for b in behaviors]
        techniques = [b.get("technique", b.get("Technique", "")).lower() for b in behaviors]
        all_text = " ".join(tags + tactics + techniques)

        if any(k in all_text for k in ["credential", "lsass", "mimikatz", "hashdump", "kerberoast"]):
            return "credential_dumping"
        if any(k in all_text for k in ["lateral", "smb", "pass-the-hash", "wmi", "psexec", "rdp"]):
            return "lateral_movement"
        if any(k in all_text for k in ["malware", "ransomware", "trojan", "backdoor", "dropper", "execution"]):
            return "malware_detection"
        return "malware_detection"
    except Exception:
        return "malware_detection"


edr_runbook_agent = LlmAgent(
    name="edr_runbook_agent",
    model=settings.model_name,
    description="Investigates CrowdStrike EDR detections using EDR-specific runbooks.",
    instruction=(
        "You are the EDRRunbookAgent. You receive a normalized CrowdStrike event as JSON. "
        "1. Call enrich_crowdstrike_event to extract threat indicators (tactics, techniques, hashes). "
        "2. Call classify_threat_type to determine the threat category. "
        "3. List available runbooks with list_edr_runbooks. "
        "4. Load the best matching runbook with load_edr_runbook "
        "   (try: malware_detection, lateral_movement, credential_dumping). "
        "5. Walk through each runbook step with the enriched context. "
        "6. Produce a JSON Finding: "
        "   {finding_id, alert_id, source='crowdstrike', severity, title, description, "
        "    remediation_steps, enrichment: {device, tactics, techniques, hashes, cmdlines}}. "
        "Return only the Finding JSON."
    ),
    tools=[
        FunctionTool(func=_list_edr_runbooks),
        FunctionTool(func=_load_edr_runbook),
        FunctionTool(func=_enrich_crowdstrike_event),
        FunctionTool(func=_classify_threat_type),
    ],
)

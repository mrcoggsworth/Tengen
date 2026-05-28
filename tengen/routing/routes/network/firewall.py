from typing import Any
from tengen.queue.queues import QUEUE_RUNBOOK_FIREWALL
from tengen.routing.registry import Route, registry


def matches(raw_payload: dict[str, Any]) -> bool:
    return (
        raw_payload.get("action") in ("DENY", "DROP", "BLOCK", "REJECT")
        or raw_payload.get("log_type") in ("firewall_deny", "ddos_flow", "pcap_summary")
        or raw_payload.get("flags") in ("SYN", "RST", "FIN,ACK")
    )


registry.register(Route(
    name="network.firewall",
    queue=QUEUE_RUNBOOK_FIREWALL,
    matcher=matches,
    description="Firewall deny logs, DDoS flow records, and PCAP summaries",
))

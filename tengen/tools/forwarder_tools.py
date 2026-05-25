import httpx

from ..config import settings
from ..models.finding import Finding


def forward_to_siem(finding: Finding) -> bool:
    if not settings.siem_endpoint:
        return False
    payload = finding.model_dump()
    try:
        resp = httpx.post(settings.siem_endpoint, json=payload, timeout=10)
        return resp.status_code < 300
    except httpx.RequestError:
        return False


def forward_to_pagerduty(finding: Finding) -> bool:
    if not settings.pagerduty_api_key:
        return False
    payload = {
        "routing_key": settings.pagerduty_api_key,
        "event_action": "trigger",
        "payload": {
            "summary": finding.title,
            "severity": finding.severity.value,
            "source": finding.source.value,
            "custom_details": finding.enrichment,
        },
    }
    try:
        resp = httpx.post(
            "https://events.pagerduty.com/v2/enqueue",
            json=payload,
            timeout=10,
        )
        return resp.status_code < 300
    except httpx.RequestError:
        return False

"""EnrichmentAgent — enriches findings with external threat intelligence."""
from __future__ import annotations

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

from ..config import settings
from ..tools.enrichment import (
    lookup_asset_context,
    lookup_domain,
    lookup_file_hash,
    lookup_ip_geo,
    lookup_ip_reputation,
    lookup_user_context,
)

enrichment_agent = LlmAgent(
    name="enrichment_agent",
    model=settings.model_name,
    description=(
        "Enriches security findings with external threat intelligence: "
        "IP reputation, geolocation, domain info, file hashes, user context, "
        "and asset inventory."
    ),
    instruction=(
        "You are the EnrichmentAgent. You receive a Finding JSON. "
        "Examine the finding's enrichment field for available indicators and enrich as follows: "
        "- If source_ip or caller_ip is present: call lookup_ip_reputation AND lookup_ip_geo. "
        "- If a domain is referenced: call lookup_domain. "
        "- If a file hash (sha256) is present: call lookup_file_hash. "
        "- If a user identity (email, UPN, service account) is present: call lookup_user_context. "
        "- If a resource ARN or asset ID is present: call lookup_asset_context. "
        "Merge all results into the finding's enrichment dict. "
        "Return the Finding JSON with the enrichment field updated. "
        "If a lookup fails (returns an 'error' key), include it in enrichment.lookup_errors "
        "and continue — do not stop for individual failures."
    ),
    tools=[
        FunctionTool(func=lookup_ip_reputation),
        FunctionTool(func=lookup_ip_geo),
        FunctionTool(func=lookup_domain),
        FunctionTool(func=lookup_file_hash),
        FunctionTool(func=lookup_user_context),
        FunctionTool(func=lookup_asset_context),
    ],
)

"""Stage 0: extracts the AWS principal from the CloudTrail payload.

Runs before any AWS-API-touching enricher. Sync and deterministic — no
network calls.
"""
from __future__ import annotations

import logging

from tengen.enrichers.context import EnricherContext, Principal

logger = logging.getLogger(__name__)


class PrincipalIdentityEnricher:
    name = "principal_identity"
    cache_ttl: int | None = None
    timeout: float = 0.5

    def run(self, ctx: EnricherContext) -> None:
        payload = ctx.alert.raw_payload
        if not isinstance(payload, dict):
            ctx.errors.append({"enricher": self.name, "error": "payload is not a dict", "type": "PreconditionError"})
            return
        user_identity = payload.get("userIdentity")
        if not isinstance(user_identity, dict):
            ctx.errors.append({"enricher": self.name, "error": "alert payload missing userIdentity", "type": "PreconditionError"})
            return
        try:
            identity_type = user_identity.get("type", "Unknown")
            arn = user_identity.get("arn", "")
            account_id = user_identity.get("accountId", "")
            is_privileged = identity_type in ("Root", "FederatedUser") or "admin" in arn.lower()
            ctx.principal = Principal(
                identity=arn or user_identity.get("userName", "unknown"),
                identity_type=identity_type,
                account_id=account_id,
                is_privileged=is_privileged,
            )
        except Exception as exc:
            logger.exception("PrincipalIdentityEnricher failed")
            ctx.errors.append({"enricher": self.name, "error": str(exc), "type": type(exc).__name__})

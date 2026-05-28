"""Stage 2: inspects resources referenced in the CloudTrail event."""
from __future__ import annotations

import logging
from typing import Any

from tengen.enrichers.cache import PrincipalCache
from tengen.enrichers.context import EnricherContext

logger = logging.getLogger(__name__)

_CACHE_TTL = 600
_NAMESPACE = "objects"


class ObjectInspectionEnricher:
    name = "object_inspection"
    cache_ttl: int | None = _CACHE_TTL
    timeout: float = 5.0

    def __init__(
        self,
        s3_client: Any,
        iam_client: Any,
        ec2_client: Any,
        cache: PrincipalCache,
    ) -> None:
        self._s3 = s3_client
        self._iam = iam_client
        self._ec2 = ec2_client
        self._cache = cache

    def run(self, ctx: EnricherContext) -> None:
        payload = ctx.alert.raw_payload
        if not isinstance(payload, dict):
            return
        resources = payload.get("resources", [])
        inspected: dict[str, dict[str, Any]] = {}
        for resource in resources[:5]:  # cap at 5 to bound latency
            arn = resource.get("ARN") or resource.get("resourceName", "")
            if not arn:
                continue
            cache_key = arn
            cached = self._cache.get(cache_key, _NAMESPACE)
            if cached is not None:
                inspected[arn] = cached
                continue
            info = self._inspect_resource(resource)
            if info:
                self._cache.set(cache_key, _NAMESPACE, info, _CACHE_TTL)
                inspected[arn] = info
        if inspected:
            ctx.extracted.setdefault("cloudtrail", {})["inspected_objects"] = inspected

    def _inspect_resource(self, resource: dict[str, Any]) -> dict[str, Any] | None:
        resource_type = resource.get("type", "")
        try:
            if "S3" in resource_type or "bucket" in resource_type.lower():
                bucket = resource.get("resourceName", "")
                if bucket:
                    resp = self._s3.get_bucket_acl(Bucket=bucket)
                    return {"type": "s3_bucket", "acl_owner": resp.get("Owner", {})}
            elif "IAM" in resource_type:
                name = resource.get("resourceName", "")
                if name:
                    resp = self._iam.get_user(UserName=name)
                    return {"type": "iam_user", "user": resp.get("User", {})}
        except Exception as exc:
            logger.debug("ObjectInspectionEnricher: could not inspect %s: %s", resource, exc)
        return None

"""CloudTrail runbook — enricher pipeline + LLM reasoning."""
from __future__ import annotations

import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import boto3

from tengen.enrichers.cache import InProcessTTLCache
from tengen.enrichers.cloud.aws.cloudtrail import (
    ObjectInspectionEnricher,
    PrincipalHistoryEnricher,
    PrincipalIdentityEnricher,
    WriteCallFilterEnricher,
)
from tengen.enrichers.context import EnricherContext
from tengen.enrichers.runner import EnricherPipeline
from tengen.metrics.emitter import MetricsEmitter
from tengen.models.alert import Alert
from tengen.models.enriched_alert import EnrichedAlert
from tengen.queue.queues import QUEUE_RUNBOOK_CLOUDTRAIL
from tengen.runbooks.base import BaseRunbook

logger = logging.getLogger(__name__)

_BUDGET_ENV = "TENGEN_ENRICHER_TOTAL_BUDGET_SECONDS"
_DEFAULT_BUDGET = 8.0
_DEFAULT_MAX_WORKERS = 8


class CloudTrailRunbook(BaseRunbook):
    source_queue = QUEUE_RUNBOOK_CLOUDTRAIL
    runbook_name = "cloud.aws.cloudtrail"

    def __init__(
        self,
        url: str | None = None,
        emitter: MetricsEmitter | None = None,
        *,
        cloudtrail_client: Any | None = None,
        s3_client: Any | None = None,
        iam_client: Any | None = None,
        ec2_client: Any | None = None,
        cache: Any | None = None,
        executor: ThreadPoolExecutor | None = None,
    ) -> None:
        super().__init__(url=url, emitter=emitter)
        self._cloudtrail = cloudtrail_client or boto3.client("cloudtrail")
        self._s3 = s3_client or boto3.client("s3")
        self._iam = iam_client or boto3.client("iam")
        self._ec2 = ec2_client or boto3.client("ec2")
        self._cache = cache or InProcessTTLCache()
        self._executor = executor or ThreadPoolExecutor(
            max_workers=_DEFAULT_MAX_WORKERS,
            thread_name_prefix="ct-enricher",
        )
        budget = float(os.getenv(_BUDGET_ENV, str(_DEFAULT_BUDGET)))
        self._pipeline = EnricherPipeline(
            stages=[
                [PrincipalIdentityEnricher()],
                [
                    PrincipalHistoryEnricher(self._cloudtrail, self._cache),
                    WriteCallFilterEnricher(),
                ],
                [ObjectInspectionEnricher(self._s3, self._iam, self._ec2, self._cache)],
            ],
            executor=self._executor,
            total_budget_seconds=budget,
        )
        logger.info("CloudTrailRunbook started (budget=%.1fs)", budget)

    def stop(self) -> None:
        super().stop()
        self._executor.shutdown(wait=False)

    def enrich(self, alert: Alert) -> EnrichedAlert:
        extracted: dict[str, Any] = {}
        runbook_error: str | None = None
        try:
            extracted.update(self._extract_basic_fields(alert))
            ctx = EnricherContext(alert=alert, extracted=extracted)
            started = time.monotonic()
            self._pipeline.run_sync(ctx)
            pipeline_ms = int((time.monotonic() - started) * 1000)
            if ctx.principal is not None:
                extracted["principal"] = ctx.principal.model_dump()
            if ctx.errors:
                extracted["enricher_errors"] = ctx.errors
            self._emit_pipeline_metrics(ctx, pipeline_ms)
        except Exception as exc:
            runbook_error = f"{type(exc).__name__}: {exc}"
            logger.error("Alert %s enrich() failed: %s", alert.id, runbook_error)

        return EnrichedAlert(alert=alert, runbook=self.runbook_name, extracted=extracted, runbook_error=runbook_error)

    def _emit_pipeline_metrics(self, ctx: EnricherContext, pipeline_ms: int) -> None:
        if self._emitter is None:
            return
        for timing in ctx.timings:
            self._emitter.emit("enricher_duration_ms", {"enricher": timing.get("enricher"), "duration_ms": timing.get("duration_ms"), "runbook": self.runbook_name})
        for err in ctx.errors:
            self._emitter.emit("enricher_error", {"enricher": err.get("enricher"), "type": err.get("type"), "runbook": self.runbook_name})
        self._emitter.emit("enricher_pipeline_ms", {"runbook": self.runbook_name, "duration_ms": pipeline_ms, "stages": ctx.stages_completed})

    @staticmethod
    def _extract_basic_fields(alert: Alert) -> dict[str, Any]:
        payload = alert.raw_payload
        if not isinstance(payload, dict):
            return {}
        extracted: dict[str, Any] = {}
        user_identity = payload.get("userIdentity", {})
        if isinstance(user_identity, dict):
            extracted["user"] = user_identity.get("userName") or user_identity.get("arn", "unknown")
            extracted["user_type"] = user_identity.get("type", "unknown")
        for src, dst in (("eventName", "event_name"), ("eventSource", "event_source"), ("awsRegion", "aws_region"), ("sourceIPAddress", "source_ip")):
            if payload.get(src) is not None:
                extracted[dst] = payload[src]
        return extracted

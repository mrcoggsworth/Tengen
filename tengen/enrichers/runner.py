"""Async pipeline runner that executes enrichers stage by stage.

Stages: list[list[Enricher]] — each inner list runs concurrently, batches
run sequentially. Each enricher executes in a ThreadPoolExecutor thread so
blocking boto3/API calls do not stall the event loop.

Two timeouts:
    enricher.timeout      — per-enricher wall-clock cap (default 3s)
    total_budget_seconds  — pipeline-wide cap (default 8s)

The runner never raises out to the caller. Exceptions are recorded in ctx.errors.
"""
from __future__ import annotations

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from tengen.enrichers.context import EnricherContext
from tengen.enrichers.protocol import Enricher

logger = logging.getLogger(__name__)

_PIPELINE_ERROR_KEY = "_pipeline_"


class EnricherPipeline:
    """Stage-list async runner with per-enricher and total-budget timeouts."""

    def __init__(
        self,
        stages: list[list[Enricher]],
        executor: ThreadPoolExecutor,
        total_budget_seconds: float = 8.0,
    ) -> None:
        if total_budget_seconds <= 0:
            raise ValueError("total_budget_seconds must be positive")
        self._stages = stages
        self._executor = executor
        self._total_budget = total_budget_seconds

    async def run(self, ctx: EnricherContext) -> None:
        """Execute every stage. Records errors in ctx.errors; never raises."""
        try:
            await asyncio.wait_for(
                self._run_all_stages(ctx),
                timeout=self._total_budget,
            )
        except asyncio.TimeoutError:
            ctx.errors.append({
                "enricher": _PIPELINE_ERROR_KEY,
                "error": f"total budget {self._total_budget}s exceeded",
                "type": "PipelineBudgetExceeded",
            })
        except Exception as exc:
            logger.exception("EnricherPipeline.run failed unexpectedly")
            ctx.errors.append({
                "enricher": _PIPELINE_ERROR_KEY,
                "error": str(exc),
                "type": type(exc).__name__,
            })

    def run_sync(self, ctx: EnricherContext) -> None:
        """Sync convenience wrapper for runbook's blocking enrich()."""
        asyncio.run(self.run(ctx))

    async def _run_all_stages(self, ctx: EnricherContext) -> None:
        for stage in self._stages:
            if not stage:
                ctx.stages_completed += 1
                continue
            await asyncio.gather(*[self._run_one(e, ctx) for e in stage])
            ctx.stages_completed += 1

    async def _run_one(self, enricher: Enricher, ctx: EnricherContext) -> None:
        loop = asyncio.get_running_loop()
        future: Any = loop.run_in_executor(self._executor, enricher.run, ctx)
        started = time.monotonic()
        try:
            await asyncio.wait_for(future, timeout=enricher.timeout)
        except asyncio.TimeoutError:
            ctx.errors.append({
                "enricher": enricher.name,
                "error": f"per-enricher timeout after {enricher.timeout}s",
                "type": "TimeoutError",
            })
        except asyncio.CancelledError:
            ctx.errors.append({
                "enricher": enricher.name,
                "error": "cancelled — pipeline total budget exhausted",
                "type": "CancelledError",
            })
            raise
        except Exception as exc:
            ctx.errors.append({
                "enricher": enricher.name,
                "error": str(exc),
                "type": type(exc).__name__,
            })
        finally:
            ctx.timings.append({
                "enricher": enricher.name,
                "duration_ms": int((time.monotonic() - started) * 1000),
            })

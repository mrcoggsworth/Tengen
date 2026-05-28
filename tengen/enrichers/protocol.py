"""The Enricher Protocol that every enricher implements.

An enricher is a small, sync, side-effect-only unit of work. The runner wraps
each enricher in asyncio.to_thread and an asyncio.wait_for timeout so blocking
boto3/API calls do not stall the event loop.

Contract:
    - run() mutates ctx in place and returns None.
    - run() MUST NOT raise. Catch internally and append to ctx.errors.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from tengen.enrichers.context import EnricherContext


@runtime_checkable
class Enricher(Protocol):
    """A single step in the enrichment pipeline."""

    name: str
    cache_ttl: int | None
    timeout: float

    def run(self, ctx: EnricherContext) -> None: ...

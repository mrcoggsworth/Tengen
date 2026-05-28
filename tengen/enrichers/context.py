"""Mutable per-alert state passed through the enricher pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tengen.models.alert import Alert


@dataclass
class Principal:
    """Normalized identity from any cloud provider."""

    identity: str
    identity_type: str
    account_id: str = ""
    is_privileged: bool = False

    def cache_key(self) -> str:
        return f"{self.identity_type}:{self.identity}"

    def model_dump(self) -> dict[str, Any]:
        return {
            "identity": self.identity,
            "identity_type": self.identity_type,
            "account_id": self.account_id,
            "is_privileged": self.is_privileged,
        }


@dataclass
class EnricherContext:
    """Carries the alert, in-progress extracted dict, and per-run state.

    Fields populated before the pipeline starts:
      - alert       — the inbound Alert
      - extracted   — pre-seeded with basic field extraction

    Fields populated by enrichers:
      - principal   — set by the principal-identity enricher in stage 0
      - errors      — appended to whenever an enricher catches an exception

    Fields populated by the runner:
      - timings           — one {"enricher", "duration_ms"} entry per enricher
      - stages_completed  — stages that finished before total budget expired
    """

    alert: Alert
    extracted: dict[str, Any] = field(default_factory=dict)
    principal: Principal | None = None
    errors: list[dict[str, str]] = field(default_factory=list)
    timings: list[dict[str, Any]] = field(default_factory=list)
    stages_completed: int = 0

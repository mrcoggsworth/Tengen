"""Thin HTTP client for the Tengen dashboard REST API."""
from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class DashboardClient:
    def __init__(self, base_url: str = "http://localhost:8080") -> None:
        self._base = base_url.rstrip("/")

    def _get(self, path: str) -> Any:
        try:
            resp = httpx.get(f"{self._base}{path}", timeout=5)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.debug("DashboardClient %s: %s", path, exc)
            return None

    def healthz(self) -> bool:
        result = self._get("/healthz")
        return isinstance(result, dict) and result.get("status") == "ok"

    def get_overview(self) -> dict[str, Any]:
        return self._get("/api/overview") or {}

    def get_queues(self) -> list[dict[str, Any]]:
        return self._get("/api/queues") or []

    def get_runbooks(self) -> list[dict[str, Any]]:
        return self._get("/api/runbooks") or []

    def get_routes(self) -> list[dict[str, Any]]:
        return self._get("/api/routes") or []

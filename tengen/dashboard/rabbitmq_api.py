"""HTTP client for the RabbitMQ Management API (live queue depths)."""
from __future__ import annotations

import logging
import os
from typing import Any

import requests

logger = logging.getLogger(__name__)


class RabbitMQApiClient:
    """Fetches live queue depths and consumer counts from the Management API."""

    def __init__(
        self,
        base_url: str | None = None,
        user: str | None = None,
        password: str | None = None,
    ) -> None:
        self._base_url = (base_url or os.environ.get("RABBITMQ_MGMT_URL", "http://localhost:15672")).rstrip("/")
        self._user = user or os.environ.get("RABBITMQ_USER", "guest")
        self._password = password or os.environ.get("RABBITMQ_PASS", "guest")

    def get_queues(self) -> list[dict[str, Any]]:
        try:
            resp = requests.get(
                f"{self._base_url}/api/queues",
                auth=(self._user, self._password),
                timeout=5,
            )
            resp.raise_for_status()
            queues = resp.json()
            return [
                {
                    "name": q.get("name"),
                    "messages": q.get("messages", 0),
                    "messages_ready": q.get("messages_ready", 0),
                    "messages_unacknowledged": q.get("messages_unacknowledged", 0),
                    "consumers": q.get("consumers", 0),
                    "message_stats": q.get("message_stats", {}),
                }
                for q in queues
            ]
        except Exception as exc:
            logger.warning("RabbitMQApiClient: could not fetch queues: %s", exc)
            return []

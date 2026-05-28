"""Splunk HTTP Event Collector (HEC) client.

Batched, retrying, with exponential backoff. Always use as a context manager.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

import requests

logger = logging.getLogger(__name__)

_DEFAULT_BATCH_SIZE = 50
_MAX_RETRY_ATTEMPTS = 3
_RETRY_BASE_DELAY = 1.0


class SplunkHECClient:
    """Sends events to Splunk via HTTP Event Collector."""

    def __init__(
        self,
        url: str | None = None,
        token: str | None = None,
        index: str | None = None,
        batch_size: int | None = None,
    ) -> None:
        self._url = (url or os.environ["SPLUNK_HEC_URL"]).rstrip("/")
        self._token = token or os.environ["SPLUNK_HEC_TOKEN"]
        self._index = index or os.environ.get("SPLUNK_INDEX", "main")
        self._batch_size = batch_size or int(os.environ.get("SPLUNK_BATCH_SIZE", str(_DEFAULT_BATCH_SIZE)))
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Splunk {self._token}",
            "Content-Type": "application/json",
        })
        self._buffer: list[dict[str, Any]] = []

    def build_event(
        self,
        event_data: dict[str, Any],
        source: str,
        sourcetype: str,
        timestamp: float | None = None,
        host: str = "tengen",
    ) -> dict[str, Any]:
        return {
            "time": timestamp if timestamp is not None else time.time(),
            "host": host,
            "source": source,
            "sourcetype": sourcetype,
            "index": self._index,
            "event": event_data,
        }

    def send(self, event: dict[str, Any]) -> None:
        self._buffer.append(event)
        if len(self._buffer) >= self._batch_size:
            self.flush()

    def flush(self) -> None:
        if not self._buffer:
            return
        batch = self._buffer[:]
        self._buffer.clear()
        payload = "\n".join(json.dumps(evt) for evt in batch)
        logger.info("Flushing %d event(s) to Splunk HEC", len(batch))
        self._post_with_retry(payload, event_count=len(batch))

    def _post_with_retry(self, payload: str, event_count: int) -> None:
        delay = _RETRY_BASE_DELAY
        for attempt in range(1, _MAX_RETRY_ATTEMPTS + 1):
            try:
                resp = self._session.post(self._url, data=payload, timeout=10)
                if resp.status_code == 200:
                    logger.info("Sent %d event(s) to Splunk (status=200)", event_count)
                    return
                if resp.status_code == 429 or resp.status_code >= 500:
                    logger.warning("Splunk HEC %d on attempt %d — retrying in %.1fs", resp.status_code, attempt, delay)
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise RuntimeError(f"Splunk HEC permanent error {resp.status_code}: {resp.text[:200]}")
            except requests.RequestException as exc:
                logger.warning("Splunk HEC request failed attempt %d: %s — retrying", attempt, exc)
                time.sleep(delay)
                delay *= 2
        raise RuntimeError(f"Failed to deliver {event_count} event(s) to Splunk HEC after {_MAX_RETRY_ATTEMPTS} attempts")

    def close(self) -> None:
        self.flush()
        self._session.close()

    def __enter__(self) -> "SplunkHECClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

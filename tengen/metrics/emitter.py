from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

from tengen.queue.queues import QUEUE_METRICS

logger = logging.getLogger(__name__)


class MetricsEmitter:
    """Fire-and-forget publisher for pipeline metric events.

    Every emit() call is fully wrapped in try/except — it never raises and
    never blocks the calling thread. The main pipeline must never be affected
    by metrics failures.

    Event schema published to tengen.metrics:
        {"event": "<name>", "ts": "<iso8601>", "data": {...}}

    Recognised event names:
        alert_ingested         — consumer received an alert
        event_normalized       — normalizer produced a NormalizedEvent
        normalization_error    — normalizer failed
        event_suppressed       — triage agent suppressed an event
        incident_created       — new incident opened
        incident_updated       — event added to existing incident
        route_matched          — router matched a route
        dlq_enqueued           — alert sent to DLQ
        runbook_success        — runbook enriched successfully
        runbook_error          — runbook raised unexpectedly
        enricher_duration_ms   — per-enricher timing
        enricher_pipeline_ms   — total pipeline timing
        enricher_error         — per-enricher error
        containment_executed   — containment action taken
        containment_skipped    — containment skipped (severity too low)
        enrichment_latency_ms  — external enrichment call timing
        enrichment_error       — external enrichment call failed
        forwarding_success     — finding forwarded downstream
        forwarding_failure     — forwarding failed
    """

    def __init__(self, url: str | None = None) -> None:
        self._url = url or os.environ.get(
            "RABBITMQ_URL", "amqp://guest:guest@localhost:5672/"
        )
        self._connection: Any = None
        self._channel: Any = None

    def emit(self, event: str, data: dict[str, Any] | None = None) -> None:
        """Publish a metric event. Never raises."""
        try:
            if not self._ensure_connected():
                return
            message: dict[str, Any] = {
                "event": event,
                "ts": datetime.now(tz=timezone.utc).isoformat(),
                "data": data or {},
            }
            body = json.dumps(message).encode()
            import pika

            props = pika.BasicProperties(
                content_type="application/json",
                delivery_mode=1,  # non-persistent — metrics are transient
            )
            if self._channel is None:
                return
            self._channel.basic_publish(
                exchange="",
                routing_key=QUEUE_METRICS,
                body=body,
                properties=props,
            )
        except Exception as exc:
            logger.debug("MetricsEmitter.emit failed (non-fatal): %s", exc)
            self._reset()

    def close(self) -> None:
        try:
            if self._connection is not None and self._connection.is_open:
                self._connection.close()
        except Exception:
            pass
        finally:
            self._reset()

    def _ensure_connected(self) -> bool:
        if (
            self._connection is not None
            and self._connection.is_open
            and self._channel is not None
            and self._channel.is_open
        ):
            return True
        try:
            import pika

            params = pika.URLParameters(self._url)
            self._connection = pika.BlockingConnection(params)
            self._channel = self._connection.channel()
            self._channel.queue_declare(queue=QUEUE_METRICS, durable=True)
            return True
        except Exception as exc:
            logger.debug("MetricsEmitter: cannot connect to RabbitMQ: %s", exc)
            self._reset()
            return False

    def _reset(self) -> None:
        self._connection = None
        self._channel = None

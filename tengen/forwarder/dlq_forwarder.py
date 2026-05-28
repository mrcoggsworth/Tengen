"""Drains the DLQ and forwards all failed alerts to Splunk HEC."""
from __future__ import annotations

import json
import logging
import os
from typing import Any

import pika

from tengen.forwarder.splunk_client import SplunkHECClient
from tengen.metrics.emitter import MetricsEmitter
from tengen.models.alert import Alert
from tengen.queue.queues import QUEUE_DLQ
from tengen.queue.rabbitmq_consumer import RabbitMQConsumer

logger = logging.getLogger(__name__)


class DLQForwarder:
    """Consumes [alerts.dlq] and forwards each DLQ entry to Splunk HEC."""

    def __init__(self, url: str | None = None, emitter: MetricsEmitter | None = None) -> None:
        self._url = url or os.environ.get("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
        self._emitter = emitter

    def run(self) -> None:
        with SplunkHECClient() as splunk:
            consumer = RabbitMQConsumer(queue=QUEUE_DLQ, url=self._url)
            with consumer:
                consumer.consume(lambda alert: self._forward_dlq(alert, splunk))

    def _forward_dlq(self, alert: Any, splunk: SplunkHECClient) -> None:
        try:
            if hasattr(alert, "model_dump"):
                data: dict[str, Any] = alert.model_dump()
            else:
                data = {"raw": str(alert)}
            event = splunk.build_event(
                event_data=data,
                source="tengen.dlq",
                sourcetype="tengen:dlq_alert",
            )
            splunk.send(event)
            if self._emitter:
                self._emitter.emit("forwarding_success", {"destination": "splunk_dlq"})
        except Exception as exc:
            logger.error("DLQForwarder failed: %s", exc)

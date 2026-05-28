"""Drains the enriched queue and forwards to Splunk HEC."""
from __future__ import annotations

import json
import logging
import os

import pika

from tengen.forwarder.splunk_client import SplunkHECClient
from tengen.metrics.emitter import MetricsEmitter
from tengen.models.enriched_alert import EnrichedAlert
from tengen.queue.queues import QUEUE_ENRICHED
from tengen.queue.rabbitmq_consumer import RabbitMQConsumer

logger = logging.getLogger(__name__)


class EnrichedAlertForwarder:
    """Consumes [enriched] queue and forwards each EnrichedAlert to Splunk HEC."""

    def __init__(self, url: str | None = None, emitter: MetricsEmitter | None = None) -> None:
        self._url = url or os.environ.get("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
        self._emitter = emitter

    def run(self) -> None:
        with SplunkHECClient() as splunk:
            consumer = RabbitMQConsumer(queue=QUEUE_ENRICHED, url=self._url)
            with consumer:
                consumer.consume(lambda alert: self._forward(alert, splunk))

    def _forward(self, alert: object, splunk: SplunkHECClient) -> None:
        try:
            if hasattr(alert, "model_dump"):
                data = alert.model_dump()  # type: ignore[union-attr]
            else:
                data = json.loads(str(alert))
            event = splunk.build_event(
                event_data=data,
                source=data.get("runbook", "tengen"),
                sourcetype="tengen:enriched_alert",
            )
            splunk.send(event)
            if self._emitter:
                self._emitter.emit("forwarding_success", {"destination": "splunk"})
        except Exception as exc:
            logger.error("EnrichedAlertForwarder failed: %s", exc)
            if self._emitter:
                self._emitter.emit("forwarding_failure", {"error": str(exc)})

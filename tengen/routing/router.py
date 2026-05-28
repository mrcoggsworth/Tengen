from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import pika
import pika.exceptions

from tengen.metrics.emitter import MetricsEmitter
from tengen.models.alert import Alert
from tengen.queue.queues import QUEUE_ALERTS, QUEUE_DLQ
from tengen.queue.rabbitmq import RabbitMQPublisher
from tengen.queue.rabbitmq_consumer import RabbitMQConsumer
from tengen.routing.registry import RouteRegistry

logger = logging.getLogger(__name__)


class Router:
    """Consumes from the alerts queue, matches each Alert to a route,
    and publishes to the appropriate runbook queue or the DLQ.

    Routing logic lives entirely in the RouteRegistry — this class only
    orchestrates connections and message flow.
    """

    def __init__(
        self,
        registry: RouteRegistry,
        url: str | None = None,
        emitter: MetricsEmitter | None = None,
    ) -> None:
        self._registry = registry
        self._url: str = url or os.environ.get(
            "RABBITMQ_URL", "amqp://guest:guest@localhost:5672/"
        )
        self._emitter = emitter
        self._consumer = RabbitMQConsumer(queue=QUEUE_ALERTS, url=url)
        self._publisher = RabbitMQPublisher(url=url)

    def run(self) -> None:
        params = pika.URLParameters(self._url)
        params.heartbeat = 60
        params.blocked_connection_timeout = 300
        shared_conn = pika.BlockingConnection(params)
        logger.info("Router: shared RabbitMQ connection opened")

        try:
            self._publisher = RabbitMQPublisher(url=self._url, connection=shared_conn)
            self._consumer = RabbitMQConsumer(
                queue=QUEUE_ALERTS, url=self._url, connection=shared_conn
            )
            with self._publisher:
                if self._publisher._channel is not None:
                    self._publisher._channel.queue_declare(queue=QUEUE_DLQ, durable=True)
                with self._consumer:
                    logger.info(
                        "Router started. Routes: %s",
                        [r.name for r in self._registry.all_routes()],
                    )
                    self._consumer.consume(self._route_alert)
        finally:
            try:
                if shared_conn.is_open:
                    shared_conn.close()
            except Exception:
                pass

    def stop(self) -> None:
        self._consumer.stop()

    def _route_alert(self, alert: Alert) -> None:
        route = self._registry.match(alert.raw_payload)
        if route is None:
            logger.warning(
                "No route matched for alert %s (source=%s) — DLQ",
                alert.id,
                alert.source,
            )
            self._publish_to_dlq(alert, reason="no_route_matched")
            return
        try:
            body = alert.model_dump_json().encode()
            props = pika.BasicProperties(content_type="application/json", delivery_mode=2)
            self._publisher.publish_to_queue(route.queue, body, props)
            logger.info("Routed alert %s -> route='%s'", alert.id, route.name)
            if self._emitter:
                self._emitter.emit("route_matched", {"route": route.name})
        except Exception as exc:
            logger.error("Failed to publish alert %s to '%s': %s — DLQ", alert.id, route.name, exc)
            self._publish_to_dlq(alert, reason="publish_failed", detail=str(exc))
            raise

    def _publish_to_dlq(self, alert: Alert, reason: str, detail: str = "") -> None:
        dlq_message: dict[str, Any] = {
            "alert": json.loads(alert.model_dump_json()),
            "dlq_reason": reason,
            "dlq_at": datetime.now(tz=timezone.utc).isoformat(),
            "error_detail": detail,
        }
        body = json.dumps(dlq_message).encode()
        props = pika.BasicProperties(content_type="application/json", delivery_mode=2)
        try:
            self._publisher.publish_to_queue(QUEUE_DLQ, body, props)
            if self._emitter:
                self._emitter.emit("dlq_enqueued", {"reason": reason})
        except Exception as exc:
            logger.error("CRITICAL: could not publish alert %s to DLQ: %s", alert.id, exc)

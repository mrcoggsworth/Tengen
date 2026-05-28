from __future__ import annotations

import json
import logging
import os
from typing import Any

import pika
import pika.adapters.blocking_connection

from .queues import QUEUE_ALERTS

logger = logging.getLogger(__name__)


class RabbitMQPublisher:
    """Publishes messages to RabbitMQ queues.

    Accepts an optional shared pika connection so the router can share one
    connection between publisher and consumer channels.
    """

    def __init__(
        self,
        url: str | None = None,
        connection: pika.BlockingConnection | None = None,
    ) -> None:
        self._url: str = url or os.environ.get(
            "RABBITMQ_URL", "amqp://guest:guest@localhost:5672/"
        )
        self._connection = connection
        self._channel: pika.adapters.blocking_connection.BlockingChannel | None = None
        self._owns_connection = connection is None

    def connect(self) -> None:
        if self._owns_connection:
            params = pika.URLParameters(self._url)
            self._connection = pika.BlockingConnection(params)
        assert self._connection is not None
        self._channel = self._connection.channel()
        self._channel.queue_declare(queue=QUEUE_ALERTS, durable=True)
        logger.info("RabbitMQPublisher connected")

    def disconnect(self) -> None:
        try:
            if self._channel and self._channel.is_open:
                self._channel.close()
        except Exception:
            pass
        try:
            if self._owns_connection and self._connection and self._connection.is_open:
                self._connection.close()
        except Exception:
            pass
        self._channel = None
        logger.info("RabbitMQPublisher disconnected")

    def publish(self, alert: Any) -> None:
        """Publish an Alert to the default alerts queue."""
        body = alert.model_dump_json().encode()
        properties = pika.BasicProperties(
            content_type="application/json",
            delivery_mode=2,
        )
        self.publish_to_queue(QUEUE_ALERTS, body, properties)

    def publish_to_queue(
        self,
        queue: str,
        body: bytes,
        properties: pika.BasicProperties | None = None,
    ) -> None:
        if self._channel is None:
            raise RuntimeError("Publisher not connected. Call connect() first.")
        self._channel.queue_declare(queue=queue, durable=True)
        self._channel.basic_publish(
            exchange="",
            routing_key=queue,
            body=body,
            properties=properties
            or pika.BasicProperties(
                content_type="application/json",
                delivery_mode=2,
            ),
        )
        logger.debug("Published to queue='%s' (%d bytes)", queue, len(body))

    def publish_json(self, queue: str, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode()
        self.publish_to_queue(queue, body)

    def __enter__(self) -> "RabbitMQPublisher":
        self.connect()
        return self

    def __exit__(self, *_: object) -> None:
        self.disconnect()

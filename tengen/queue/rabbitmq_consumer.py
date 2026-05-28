from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable
from typing import Any

import pika
import pika.adapters.blocking_connection

from tengen.models.alert import Alert

logger = logging.getLogger(__name__)


class RabbitMQConsumer:
    """Consumes messages from a single RabbitMQ queue.

    Deserializes each message as an Alert and invokes the callback.
    Nacks without requeue on deserialization failure; acks on success.
    """

    def __init__(
        self,
        queue: str,
        url: str | None = None,
        connection: pika.BlockingConnection | None = None,
        prefetch_count: int = 1,
    ) -> None:
        self._queue = queue
        self._url: str = url or os.environ.get(
            "RABBITMQ_URL", "amqp://guest:guest@localhost:5672/"
        )
        self._connection = connection
        self._channel: pika.adapters.blocking_connection.BlockingChannel | None = None
        self._owns_connection = connection is None
        self._prefetch_count = prefetch_count
        self._running = False

    def connect(self) -> None:
        if self._owns_connection:
            params = pika.URLParameters(self._url)
            self._connection = pika.BlockingConnection(params)
        assert self._connection is not None
        self._channel = self._connection.channel()
        self._channel.queue_declare(queue=self._queue, durable=True)
        self._channel.basic_qos(prefetch_count=self._prefetch_count)
        self._running = True
        logger.info("RabbitMQConsumer connected to queue='%s'", self._queue)

    def consume(self, callback: Callable[[Alert], None]) -> None:
        if self._channel is None:
            raise RuntimeError("Consumer not connected. Call connect() first.")

        def _on_message(
            ch: Any,
            method: Any,
            _properties: Any,
            body: bytes,
        ) -> None:
            try:
                alert = Alert.model_validate_json(body)
            except Exception as exc:
                logger.error(
                    "Failed to deserialize message from queue='%s': %s",
                    self._queue,
                    exc,
                )
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
                return
            try:
                callback(alert)
                ch.basic_ack(delivery_tag=method.delivery_tag)
            except Exception as exc:
                logger.error(
                    "Callback raised for alert %s: %s — nacking",
                    getattr(alert, "id", "?"),
                    exc,
                )
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)

        self._channel.basic_consume(
            queue=self._queue,
            on_message_callback=_on_message,
        )
        logger.info("RabbitMQConsumer starting consume loop on queue='%s'", self._queue)
        self._channel.start_consuming()

    def stop(self) -> None:
        self._running = False
        if self._channel and self._channel.is_open:
            try:
                self._channel.stop_consuming()
            except Exception:
                pass

    def disconnect(self) -> None:
        self.stop()
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
        logger.info("RabbitMQConsumer disconnected from queue='%s'", self._queue)

    def __enter__(self) -> "RabbitMQConsumer":
        self.connect()
        return self

    def __exit__(self, *_: object) -> None:
        self.disconnect()

"""Background thread that drains the tengen.metrics queue and updates MetricsStore."""
from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any

logger = logging.getLogger(__name__)


class MetricsConsumer:
    """Connects to RabbitMQ, drains tengen.metrics, increments MetricsStore counters."""

    def __init__(self, store: Any, url: str | None = None) -> None:
        self._store = store
        self._url = url or os.environ.get("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
        self._thread: threading.Thread | None = None
        self._running = False

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._consume_loop, daemon=True, name="metrics-consumer")
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def _consume_loop(self) -> None:
        while self._running:
            try:
                import pika
                from tengen.queue.queues import QUEUE_METRICS

                params = pika.URLParameters(self._url)
                conn = pika.BlockingConnection(params)
                channel = conn.channel()
                channel.queue_declare(queue=QUEUE_METRICS, durable=True)

                def on_message(ch: Any, method: Any, _props: Any, body: bytes) -> None:
                    try:
                        msg: dict[str, Any] = json.loads(body)
                        self._store.record_event(msg.get("event", ""), msg.get("data", {}))
                        ch.basic_ack(delivery_tag=method.delivery_tag)
                    except Exception as exc:
                        logger.debug("MetricsConsumer: failed to process message: %s", exc)
                        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

                channel.basic_consume(queue=QUEUE_METRICS, on_message_callback=on_message)
                channel.start_consuming()
            except Exception as exc:
                if self._running:
                    logger.debug("MetricsConsumer connection lost: %s — reconnecting", exc)
                    import time
                    time.sleep(5)

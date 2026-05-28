from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable

from tengen.consumers.base import BaseConsumer
from tengen.metrics.emitter import MetricsEmitter
from tengen.models.alert import Alert

logger = logging.getLogger(__name__)

_POLL_TIMEOUT_SECONDS = 1.0


class KafkaConsumer(BaseConsumer):
    """Consumes alerts from Apache Kafka topics.

    Config env vars: KAFKA_BOOTSTRAP_SERVERS, KAFKA_GROUP_ID, KAFKA_TOPICS
    Requires: confluent-kafka
    """

    def __init__(
        self,
        bootstrap_servers: str | None = None,
        group_id: str | None = None,
        topics: list[str] | None = None,
        emitter: MetricsEmitter | None = None,
    ) -> None:
        self._bootstrap_servers = bootstrap_servers or os.environ.get(
            "KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"
        )
        self._group_id = group_id or os.environ.get(
            "KAFKA_GROUP_ID", "tengen-consumer-group"
        )
        raw_topics = os.environ.get("KAFKA_TOPICS", "security-alerts")
        self._topics = topics or raw_topics.split(",")
        self._emitter = emitter
        self._consumer: object | None = None
        self._running = False

    def connect(self) -> None:
        from confluent_kafka import Consumer  # type: ignore[import]

        self._consumer = Consumer(
            {
                "bootstrap.servers": self._bootstrap_servers,
                "group.id": self._group_id,
                "auto.offset.reset": "earliest",
                "enable.auto.commit": False,
            }
        )
        self._consumer.subscribe(self._topics)  # type: ignore[union-attr]
        self._running = True
        logger.info("KafkaConsumer subscribed to topics=%s", self._topics)

    def consume(self, callback: Callable[[Alert], None]) -> None:
        if self._consumer is None:
            raise RuntimeError("Not connected. Call connect() first.")
        while self._running:
            msg = self._consumer.poll(_POLL_TIMEOUT_SECONDS)  # type: ignore[union-attr]
            if msg is None:
                continue
            if msg.error():
                logger.error("KafkaConsumer error: %s", msg.error())
                continue
            try:
                payload = json.loads(msg.value())
                alert = Alert(
                    source="kafka",
                    raw_payload=payload,
                    metadata={
                        "topic": msg.topic(),
                        "partition": msg.partition(),
                        "offset": msg.offset(),
                        "key": msg.key().decode() if msg.key() else None,
                    },
                )
                if self._emitter:
                    self._emitter.emit("alert_ingested", {"source": "kafka"})
                callback(alert)
                self._consumer.commit(message=msg)  # type: ignore[union-attr]
            except Exception as exc:
                logger.exception("KafkaConsumer failed on message: %s", exc)

    def stop(self) -> None:
        self._running = False

    def disconnect(self) -> None:
        self._running = False
        if self._consumer:
            self._consumer.close()  # type: ignore[union-attr]
            self._consumer = None
        logger.info("KafkaConsumer disconnected")

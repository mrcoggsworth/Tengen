from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable

from tengen.consumers.base import BaseConsumer
from tengen.metrics.emitter import MetricsEmitter
from tengen.models.alert import Alert

logger = logging.getLogger(__name__)


class PubSubConsumer(BaseConsumer):
    """Consumes alerts from GCP Pub/Sub pull subscription.

    Config env vars: PUBSUB_PROJECT_ID, PUBSUB_SUBSCRIPTION_ID,
                     PUBSUB_EMULATOR_HOST (local dev)
    """

    def __init__(
        self,
        project_id: str | None = None,
        subscription_id: str | None = None,
        emitter: MetricsEmitter | None = None,
        max_messages: int = 10,
    ) -> None:
        self._project_id = project_id or os.environ["PUBSUB_PROJECT_ID"]
        self._subscription_id = subscription_id or os.environ["PUBSUB_SUBSCRIPTION_ID"]
        self._emitter = emitter
        self._max_messages = max_messages
        self._subscriber: object | None = None
        self._subscription_path: str = ""
        self._running = False

    def connect(self) -> None:
        from google.cloud import pubsub_v1  # type: ignore[import]

        self._subscriber = pubsub_v1.SubscriberClient()
        self._subscription_path = (
            self._subscriber.subscription_path(  # type: ignore[union-attr]
                self._project_id, self._subscription_id
            )
        )
        self._running = True
        logger.info("PubSubConsumer connected to %s", self._subscription_path)

    def consume(self, callback: Callable[[Alert], None]) -> None:
        if self._subscriber is None:
            raise RuntimeError("Not connected. Call connect() first.")
        while self._running:
            try:
                response = self._subscriber.pull(  # type: ignore[union-attr]
                    request={
                        "subscription": self._subscription_path,
                        "max_messages": self._max_messages,
                    }
                )
            except KeyboardInterrupt:
                return
            except Exception as exc:
                logger.error("PubSubConsumer pull error: %s", exc)
                continue

            ack_ids = []
            for received in response.received_messages:
                try:
                    payload = json.loads(received.message.data)
                    alert = Alert(
                        source="pubsub",
                        raw_payload=payload,
                        metadata={
                            "message_id": received.message.message_id,
                            "publish_time": str(received.message.publish_time),
                            "attributes": dict(received.message.attributes),
                        },
                    )
                    if self._emitter:
                        self._emitter.emit("alert_ingested", {"source": "pubsub"})
                    callback(alert)
                    ack_ids.append(received.ack_id)
                except Exception as exc:
                    logger.exception("PubSubConsumer failed on message: %s", exc)

            if ack_ids:
                self._subscriber.acknowledge(  # type: ignore[union-attr]
                    request={"subscription": self._subscription_path, "ack_ids": ack_ids}
                )

    def stop(self) -> None:
        self._running = False

    def disconnect(self) -> None:
        self._running = False
        if self._subscriber:
            self._subscriber.close()  # type: ignore[union-attr]
            self._subscriber = None
        logger.info("PubSubConsumer disconnected")

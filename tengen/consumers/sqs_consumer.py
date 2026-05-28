from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Callable

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from tengen.consumers.base import BaseConsumer
from tengen.metrics.emitter import MetricsEmitter
from tengen.models.alert import Alert

logger = logging.getLogger(__name__)

_POLL_WAIT_SECONDS = 20
_MAX_MESSAGES = 10
_HEARTBEAT_EVERY_N_POLLS = 6
_TRANSIENT_ERROR_BACKOFF_SECONDS = 5


class SqsConsumer(BaseConsumer):
    """Consumes alerts from AWS SQS with automatic SNS envelope unwrapping.

    Config env vars: SQS_QUEUE_URL, AWS_REGION, AWS_ENDPOINT_URL (LocalStack)
    """

    def __init__(
        self,
        queue_url: str | None = None,
        region: str | None = None,
        endpoint_url: str | None = None,
        emitter: MetricsEmitter | None = None,
    ) -> None:
        self._queue_url = queue_url or os.environ["SQS_QUEUE_URL"]
        self._region = region or os.environ.get("AWS_REGION", "us-east-1")
        self._endpoint_url = endpoint_url or os.environ.get("AWS_ENDPOINT_URL")
        self._sqs: object | None = None
        self._running = False
        self._emitter = emitter

    def connect(self) -> None:
        kwargs: dict = {
            "region_name": self._region,
            "config": Config(retries={"max_attempts": 3, "mode": "standard"}),
        }
        if self._endpoint_url:
            kwargs["endpoint_url"] = self._endpoint_url
        self._sqs = boto3.client("sqs", **kwargs)
        self._running = True
        logger.info("SqsConsumer connected to %s", self._queue_url)

    def consume(self, callback: Callable[[Alert], None]) -> None:
        if self._sqs is None:
            raise RuntimeError("Not connected. Call connect() first.")
        self._running = True
        polls = 0
        total = 0
        while self._running:
            try:
                response = self._sqs.receive_message(  # type: ignore[union-attr]
                    QueueUrl=self._queue_url,
                    MaxNumberOfMessages=_MAX_MESSAGES,
                    WaitTimeSeconds=_POLL_WAIT_SECONDS,
                    AttributeNames=["All"],
                )
            except KeyboardInterrupt:
                return
            except (ClientError, BotoCoreError) as exc:
                logger.error("SqsConsumer transient error: %s — backing off", exc)
                time.sleep(_TRANSIENT_ERROR_BACKOFF_SECONDS)
                continue

            polls += 1
            messages = response.get("Messages", [])
            total += len(messages)
            for msg in messages:
                try:
                    self._handle_message(msg, callback)
                except Exception as exc:
                    logger.exception("SqsConsumer failed on message %s: %s", msg.get("MessageId"), exc)

            if polls % _HEARTBEAT_EVERY_N_POLLS == 0:
                logger.info("SqsConsumer heartbeat: polls=%d messages=%d", polls, total)

    def _handle_message(self, msg: dict, callback: Callable[[Alert], None]) -> None:
        try:
            body: dict = json.loads(msg.get("Body", "{}"))
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse SQS body: %s", exc)
            return

        # Unwrap SNS envelope if present
        if body.get("Type") == "Notification" and "Message" in body:
            try:
                payload: dict = json.loads(body["Message"])
            except (json.JSONDecodeError, TypeError):
                payload = {"message": body["Message"]}
        else:
            payload = body

        alert = Alert(
            source="sqs",
            raw_payload=payload,
            metadata={
                "message_id": msg.get("MessageId"),
                "receipt_handle": msg.get("ReceiptHandle"),
                "topic_arn": body.get("TopicArn"),
            },
        )
        if self._emitter:
            self._emitter.emit("alert_ingested", {"source": "sqs"})
        callback(alert)
        self._sqs.delete_message(  # type: ignore[union-attr]
            QueueUrl=self._queue_url,
            ReceiptHandle=msg["ReceiptHandle"],
        )

    def stop(self) -> None:
        self._running = False

    def disconnect(self) -> None:
        self._running = False
        self._sqs = None
        logger.info("SqsConsumer disconnected")

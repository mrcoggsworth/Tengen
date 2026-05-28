"""Universal HTTP push consumer.

Exposes POST /ingest for ad-hoc integrations and webhook deliveries.
Supports optional shared-secret auth via UNIVERSAL_HTTP_TOKEN.

Start standalone:  python -m tengen.consumers.universal_consumer
"""
from __future__ import annotations

import logging
import os
from collections.abc import Callable
from typing import Any

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from tengen.consumers.base import BaseConsumer
from tengen.metrics.emitter import MetricsEmitter
from tengen.models.alert import Alert

logger = logging.getLogger(__name__)


class _IngestRequest(BaseModel):
    raw_payload: dict[str, Any]
    metadata: dict[str, Any] = Field(default_factory=dict)
    source: str = "universal"


class UniversalHTTPConsumer(BaseConsumer):
    """FastAPI-based HTTP consumer exposing POST /ingest."""

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        token: str | None = None,
        emitter: MetricsEmitter | None = None,
    ) -> None:
        self._host = host or os.environ.get("UNIVERSAL_HTTP_HOST", "0.0.0.0")
        self._port = (
            port if port is not None
            else int(os.environ.get("UNIVERSAL_HTTP_PORT", "8090"))
        )
        self._token = token if token is not None else os.environ.get("UNIVERSAL_HTTP_TOKEN")
        self._emitter = emitter
        self._callback: Callable[[Alert], None] | None = None
        self._app: FastAPI | None = None
        self._server: uvicorn.Server | None = None

    def _build_app(self) -> FastAPI:
        app = FastAPI(title="Tengen Universal Ingest")

        @app.post("/ingest", status_code=202)
        async def ingest(
            body: _IngestRequest,
            request: Request,
            authorization: str | None = Header(default=None),
        ) -> dict[str, str]:
            self._check_auth(authorization)
            alert = Alert(
                source=body.source,
                raw_payload=body.raw_payload,
                metadata={
                    **body.metadata,
                    "remote_addr": request.client.host if request.client else None,
                },
            )
            if self._emitter:
                self._emitter.emit("alert_ingested", {"source": alert.source})
            if self._callback is None:
                raise HTTPException(status_code=503, detail="consumer not ready")
            self._callback(alert)
            return {"alert_id": alert.id}

        @app.get("/healthz")
        async def healthz() -> dict[str, str]:
            return {"status": "ok"}

        return app

    def _check_auth(self, authorization: str | None) -> None:
        if not self._token:
            return
        if authorization != f"Bearer {self._token}":
            raise HTTPException(status_code=401, detail="invalid or missing token")

    def connect(self) -> None:
        self._app = self._build_app()
        logger.info("UniversalHTTPConsumer ready on %s:%d", self._host, self._port)

    def consume(self, callback: Callable[[Alert], None]) -> None:
        if self._app is None:
            raise RuntimeError("Not connected. Call connect() first.")
        self._callback = callback
        config = uvicorn.Config(self._app, host=self._host, port=self._port, log_level="info", access_log=False)
        self._server = uvicorn.Server(config)
        self._server.run()

    def stop(self) -> None:
        if self._server:
            self._server.should_exit = True

    def disconnect(self) -> None:
        self._callback = None
        self._server = None
        self._app = None
        logger.info("UniversalHTTPConsumer disconnected")


def _main() -> None:
    import logging as _logging
    import sys as _sys
    from tengen.queue.rabbitmq import RabbitMQPublisher

    _logging.basicConfig(level=_logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=_sys.stdout)
    emitter = MetricsEmitter()
    consumer = UniversalHTTPConsumer(emitter=emitter)
    publisher = RabbitMQPublisher()
    publisher.connect()
    consumer.connect()
    try:
        consumer.consume(publisher.publish)
    except KeyboardInterrupt:
        consumer.stop()
    finally:
        consumer.disconnect()
        publisher.disconnect()
        emitter.close()


if __name__ == "__main__":
    _main()

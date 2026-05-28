from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncGenerator

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse

from tengen.dashboard.metrics_consumer import MetricsConsumer
from tengen.dashboard.metrics_store import MetricsStore
from tengen.dashboard.rabbitmq_api import RabbitMQApiClient
from tengen.dashboard.routes_reader import get_routes, get_runbooks

logger = logging.getLogger(__name__)

_STATIC_DIR = Path(__file__).parent / "static"

_store = MetricsStore(db_path=os.environ.get("METRICS_DB_PATH", "/tmp/tengen_metrics.db"))
_consumer = MetricsConsumer(store=_store)
_rmq_api = RabbitMQApiClient(base_url=os.environ.get("RABBITMQ_MGMT_URL", "http://localhost:15672"))


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    _store.start_snapshot_thread()
    _consumer.start()
    logger.info("Tengen Dashboard ready")
    yield
    _consumer.stop()
    _store.stop()
    logger.info("Tengen Dashboard shutdown complete")


app = FastAPI(
    title="Tengen Security Dashboard",
    description="Real-time observability for the Tengen agentic security harness",
    version="1.0.0",
    lifespan=_lifespan,
)


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(_STATIC_DIR / "index.html")


@app.get("/api/queues")
def api_queues() -> list[dict[str, Any]]:
    return _rmq_api.get_queues()


@app.get("/api/metrics")
def api_metrics() -> dict[str, Any]:
    return _store.snapshot()


@app.get("/api/routes")
def api_routes() -> list[dict[str, Any]]:
    return get_routes()


@app.get("/api/runbooks")
def api_runbooks() -> list[dict[str, Any]]:
    return get_runbooks()


@app.get("/api/overview")
def api_overview() -> dict[str, Any]:
    snap = _store.snapshot()
    queues = _rmq_api.get_queues()
    total_ingested = sum(snap["alert_ingested"].values())
    total_processed = sum(snap["runbook_success"].values())
    total_errors = sum(snap["runbook_error"].values())
    dlq_queue = next((q for q in queues if q["name"] == "alerts.dlq"), None)
    dlq_count = int(dlq_queue["messages"]) if dlq_queue else sum(snap["dlq_counts"].values())
    return {
        "total_ingested": total_ingested,
        "total_processed": total_processed,
        "total_errors": total_errors,
        "dlq_count": dlq_count,
        "queue_count": len(queues),
        "containment_actions": sum(snap["containment_executed"].values()),
        "normalization_counts": snap["normalization_counts"],
    }


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}

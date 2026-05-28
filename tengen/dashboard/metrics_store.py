from __future__ import annotations

import logging
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_SNAPSHOT_INTERVAL_SECONDS = 60


class MetricsStore:
    """Thread-safe in-memory counter store with SQLite persistence.

    Counters survive pod restarts. A background thread flushes every 60s.
    Use db_path=":memory:" in unit tests.
    """

    def __init__(self, db_path: str = "/tmp/tengen_metrics.db") -> None:
        self._lock = threading.Lock()
        self._db_path = db_path

        self.route_counts: dict[str, int] = {}
        self.runbook_success: dict[str, int] = {}
        self.runbook_error: dict[str, int] = {}
        self.alert_ingested: dict[str, int] = {}
        self.dlq_counts: dict[str, int] = {}
        self.containment_executed: dict[str, int] = {}
        self.normalization_counts: dict[str, int] = {}

        self._snapshot_thread: threading.Thread | None = None
        self._running = False
        self._init_db()
        self._load_from_db()

    def increment(self, counter: dict[str, int], key: str, amount: int = 1) -> None:
        with self._lock:
            counter[key] = counter.get(key, 0) + amount

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "route_counts": dict(self.route_counts),
                "runbook_success": dict(self.runbook_success),
                "runbook_error": dict(self.runbook_error),
                "alert_ingested": dict(self.alert_ingested),
                "dlq_counts": dict(self.dlq_counts),
                "containment_executed": dict(self.containment_executed),
                "normalization_counts": dict(self.normalization_counts),
            }

    def record_event(self, event: str, data: dict[str, Any]) -> None:
        """Route a metric event to the appropriate counter bucket."""
        if event == "alert_ingested":
            self.increment(self.alert_ingested, data.get("source", "unknown"))
        elif event == "route_matched":
            self.increment(self.route_counts, data.get("route", "unknown"))
        elif event == "dlq_enqueued":
            self.increment(self.dlq_counts, data.get("reason", "unknown"))
        elif event == "runbook_success":
            self.increment(self.runbook_success, data.get("runbook", "unknown"))
        elif event == "runbook_error":
            self.increment(self.runbook_error, data.get("runbook", "unknown"))
        elif event == "containment_executed":
            self.increment(self.containment_executed, data.get("action", "unknown"))
        elif event == "event_normalized":
            self.increment(self.normalization_counts, data.get("source_type", "unknown"))

    def start_snapshot_thread(self) -> None:
        if self._snapshot_thread is not None:
            return
        self._running = True
        self._snapshot_thread = threading.Thread(target=self._flush_loop, daemon=True, name="metrics-snapshot")
        self._snapshot_thread.start()

    def stop(self) -> None:
        self._running = False
        self._save_to_db()

    def _init_db(self) -> None:
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS tengen_metrics (
                        key TEXT PRIMARY KEY,
                        value INTEGER NOT NULL DEFAULT 0,
                        updated_at TEXT
                    )
                """)
                conn.commit()
        except Exception as exc:
            logger.warning("MetricsStore: could not init SQLite: %s", exc)

    def _load_from_db(self) -> None:
        try:
            with sqlite3.connect(self._db_path) as conn:
                rows = conn.execute("SELECT key, value FROM tengen_metrics").fetchall()
            for key, value in rows:
                bucket, _, name = key.partition(":")
                target = self._bucket_by_name(bucket)
                if target is not None:
                    target[name] = value
        except Exception as exc:
            logger.warning("MetricsStore: could not load from SQLite: %s", exc)

    def _save_to_db(self) -> None:
        snap = self.snapshot()
        now = datetime.now(tz=timezone.utc).isoformat()
        rows = [(f"{bucket}:{name}", value, now) for bucket, counters in snap.items() for name, value in counters.items()]
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.executemany(
                    "INSERT INTO tengen_metrics (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                    rows,
                )
                conn.commit()
        except Exception as exc:
            logger.warning("MetricsStore: SQLite flush failed: %s", exc)

    def _flush_loop(self) -> None:
        while self._running:
            time.sleep(_SNAPSHOT_INTERVAL_SECONDS)
            if self._running:
                self._save_to_db()

    def _bucket_by_name(self, name: str) -> dict[str, int] | None:
        mapping: dict[str, dict[str, int]] = {
            "route_counts": self.route_counts,
            "runbook_success": self.runbook_success,
            "runbook_error": self.runbook_error,
            "alert_ingested": self.alert_ingested,
            "dlq_counts": self.dlq_counts,
            "containment_executed": self.containment_executed,
            "normalization_counts": self.normalization_counts,
        }
        return mapping.get(name)

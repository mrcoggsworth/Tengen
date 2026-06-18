"""UDM field registry — the table of discovered/unmapped fields.

A deliberately low-resource store (SQLite by default, single file, no server)
kept *separate* from the metrics database. Every time the parser sees a raw
field that the UDM model does not yet represent, it ``observe()``s it here:
new rows are inserted, repeats bump an occurrence counter and ``last_seen``.

The table is the review queue that drives model updates: an analyst (via the
dashboard) approves a candidate, and :mod:`tengen.udm.model_updater` turns
approved rows into proposed Pydantic fields on a new branch + pull request.

Set ``TENGEN_UDM_REGISTRY_DB`` to relocate the database; use ``:memory:`` in
tests (a single shared connection keeps the in-memory DB alive).
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class FieldStatus(str, Enum):
    """Lifecycle of a discovered field candidate."""

    NEW = "new"            # just discovered, awaiting review
    APPROVED = "approved"  # analyst approved → eligible for a model-update PR
    PROMOTED = "promoted"  # a PR adding it to the model has been opened/merged
    IGNORED = "ignored"    # analyst decided it should not be modeled


def _default_db_path() -> str:
    return os.environ.get("TENGEN_UDM_REGISTRY_DB", "/tmp/tengen_udm_fields.db")


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _value_type(value: Any) -> str:
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "dict"
    return "str"


def _sample(value: Any) -> str:
    try:
        text = value if isinstance(value, str) else json.dumps(value, default=str)
    except (TypeError, ValueError):
        text = str(value)
    return text[:512]


class FieldRegistry:
    """Thread-safe SQLite-backed registry of discovered UDM field candidates."""

    def __init__(self, db_path: str | None = None) -> None:
        self._db_path = db_path or _default_db_path()
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS udm_field_candidates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_type TEXT NOT NULL,
                    raw_path TEXT NOT NULL,
                    suggested_udm_field TEXT NOT NULL DEFAULT '',
                    value_type TEXT NOT NULL DEFAULT 'str',
                    sample_value TEXT NOT NULL DEFAULT '',
                    occurrence_count INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'new',
                    notes TEXT NOT NULL DEFAULT '',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    UNIQUE(source_type, raw_path)
                )
                """
            )
            self._conn.commit()

    # ── Write path ────────────────────────────────────────────────────────────

    def observe(
        self,
        source_type: str,
        raw_path: str,
        sample_value: Any = "",
        suggested_udm_field: str = "",
    ) -> None:
        """Record one sighting of a raw field. Upserts on (source_type, raw_path)."""
        now = _now()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO udm_field_candidates
                    (source_type, raw_path, suggested_udm_field, value_type,
                     sample_value, occurrence_count, status, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
                ON CONFLICT(source_type, raw_path) DO UPDATE SET
                    occurrence_count = occurrence_count + 1,
                    last_seen = excluded.last_seen,
                    sample_value = excluded.sample_value,
                    -- keep an existing suggestion unless we now have a better one
                    suggested_udm_field = CASE
                        WHEN udm_field_candidates.suggested_udm_field = ''
                        THEN excluded.suggested_udm_field
                        ELSE udm_field_candidates.suggested_udm_field END
                """,
                (
                    source_type,
                    raw_path,
                    suggested_udm_field,
                    _value_type(sample_value),
                    _sample(sample_value),
                    FieldStatus.NEW.value,
                    now,
                    now,
                ),
            )
            self._conn.commit()

    def set_status(self, field_id: int, status: FieldStatus | str, notes: str | None = None) -> bool:
        status_value = status.value if isinstance(status, FieldStatus) else str(status)
        with self._lock:
            if notes is None:
                cur = self._conn.execute(
                    "UPDATE udm_field_candidates SET status = ?, last_seen = ? WHERE id = ?",
                    (status_value, _now(), field_id),
                )
            else:
                cur = self._conn.execute(
                    "UPDATE udm_field_candidates SET status = ?, notes = ?, last_seen = ? WHERE id = ?",
                    (status_value, notes, _now(), field_id),
                )
            self._conn.commit()
            return cur.rowcount > 0

    def set_suggested_field(self, field_id: int, suggested_udm_field: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE udm_field_candidates SET suggested_udm_field = ?, last_seen = ? WHERE id = ?",
                (suggested_udm_field, _now(), field_id),
            )
            self._conn.commit()
            return cur.rowcount > 0

    # ── Read path ─────────────────────────────────────────────────────────────

    def get(self, field_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM udm_field_candidates WHERE id = ?", (field_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_fields(
        self,
        status: FieldStatus | str | None = None,
        source_type: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if status is not None:
            clauses.append("status = ?")
            params.append(status.value if isinstance(status, FieldStatus) else str(status))
        if source_type is not None:
            clauses.append("source_type = ?")
            params.append(source_type)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM udm_field_candidates {where} "
                "ORDER BY occurrence_count DESC, last_seen DESC LIMIT ?",
                params,
            ).fetchall()
        return [dict(r) for r in rows]

    def approved_fields(self) -> list[dict[str, Any]]:
        return self.list_fields(status=FieldStatus.APPROVED)

    def summary(self) -> dict[str, Any]:
        with self._lock:
            by_status = {
                r["status"]: r["n"]
                for r in self._conn.execute(
                    "SELECT status, COUNT(*) AS n FROM udm_field_candidates GROUP BY status"
                ).fetchall()
            }
            by_source = {
                r["source_type"]: r["n"]
                for r in self._conn.execute(
                    "SELECT source_type, COUNT(*) AS n FROM udm_field_candidates GROUP BY source_type"
                ).fetchall()
            }
            total = self._conn.execute(
                "SELECT COUNT(*) AS n FROM udm_field_candidates"
            ).fetchone()["n"]
        return {
            "total": total,
            "new": by_status.get(FieldStatus.NEW.value, 0),
            "approved": by_status.get(FieldStatus.APPROVED.value, 0),
            "promoted": by_status.get(FieldStatus.PROMOTED.value, 0),
            "ignored": by_status.get(FieldStatus.IGNORED.value, 0),
            "by_status": by_status,
            "by_source": by_source,
        }

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:  # pragma: no cover - best effort
                pass

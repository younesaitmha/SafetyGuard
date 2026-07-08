from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from .config import settings

logger = logging.getLogger("sqlite_store")


class SQLiteStateStore:
    def __init__(self, db_path: str):
        path_obj = Path(db_path)
        if str(path_obj) != ":memory:":
            path_obj.parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(str(path_obj), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS state_kv (
                    namespace TEXT,
                    key TEXT,
                    payload TEXT,
                    updated_at REAL,
                    PRIMARY KEY(namespace, key)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rate_limit_hits (
                    key TEXT,
                    ts REAL
                )
                """
            )
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_rate_limit_hits_key_ts ON rate_limit_hits(key, ts)")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rate_limit_cooldowns (
                    key TEXT PRIMARY KEY,
                    cooldown_until REAL
                )
                """
            )
            self._conn.commit()

    def get_json(self, namespace: str, key: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT payload FROM state_kv WHERE namespace = ? AND key = ?",
                [namespace, key],
            ).fetchone()
        if not row:
            return None
        try:
            return json.loads(row[0])
        except Exception:
            return None

    def put_json(self, namespace: str, key: str, payload: dict[str, Any]) -> None:
        payload_json = json.dumps(payload)
        now = time.time()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO state_kv(namespace, key, payload, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(namespace, key)
                DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at
                """,
                [namespace, key, payload_json, now],
            )
            self._conn.commit()

    def list_json(self, namespace: str, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT payload FROM state_kv WHERE namespace = ? ORDER BY updated_at DESC LIMIT ?",
                [namespace, limit],
            ).fetchall()
        out: list[dict[str, Any]] = []
        for (payload,) in rows:
            try:
                out.append(json.loads(payload))
            except Exception:
                continue
        return out

    def get_cooldown(self, key: str) -> float:
        with self._lock:
            row = self._conn.execute(
                "SELECT cooldown_until FROM rate_limit_cooldowns WHERE key = ?",
                [key],
            ).fetchone()
        return float(row[0]) if row else 0.0

    def set_cooldown(self, key: str, cooldown_until: float) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO rate_limit_cooldowns(key, cooldown_until)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET cooldown_until = excluded.cooldown_until
                """,
                [key, cooldown_until],
            )
            self._conn.commit()

    def add_hit(self, key: str, ts: float) -> None:
        with self._lock:
            self._conn.execute("INSERT INTO rate_limit_hits(key, ts) VALUES (?, ?)", [key, ts])
            self._conn.commit()

    def prune_hits(self, key: str, min_ts: float) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM rate_limit_hits WHERE key = ? AND ts < ?", [key, min_ts])
            self._conn.commit()

    def count_hits(self, key: str, min_ts: float) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM rate_limit_hits WHERE key = ? AND ts >= ?",
                [key, min_ts],
            ).fetchone()
        return int(row[0]) if row else 0


_STORE: SQLiteStateStore | None = None


def get_state_store() -> SQLiteStateStore | None:
    global _STORE
    if settings.state_backend.lower() not in {"sqlite", "sqllite"}:
        return None
    if _STORE is not None:
        return _STORE
    try:
        _STORE = SQLiteStateStore(settings.state_db_path)
        return _STORE
    except Exception as exc:  # pragma: no cover - fallback path
        logger.warning("sqlite_state_store_unavailable reason=%s", type(exc).__name__)
        return None
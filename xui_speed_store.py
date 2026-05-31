from __future__ import annotations

import hashlib
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


DB_FILE = Path(os.environ.get("DB_FILE", "xui_speed_history.db"))


def panel_id(panel: dict[str, Any]) -> str:
    raw = f"{panel.get('base_url', '')}|{panel.get('username', '')}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def connect(db_path: Path | str = DB_FILE) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    return connection


def init_db(db_path: Path | str = DB_FILE) -> None:
    with connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS readings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                panel_id TEXT NOT NULL,
                panel_name TEXT NOT NULL,
                base_url TEXT NOT NULL,
                checked_at TEXT NOT NULL,
                ok INTEGER NOT NULL,
                upload_bps REAL,
                download_bps REAL,
                upload_source TEXT,
                download_source TEXT,
                error TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_readings_panel_time
            ON readings (panel_id, checked_at)
            """
        )


def save_reading(
    panel: dict[str, Any],
    checked_at: str,
    *,
    ok: bool,
    data: dict[str, Any] | None = None,
    error: str | None = None,
    db_path: Path | str = DB_FILE,
) -> None:
    init_db(db_path)
    data = data or {}
    speed_source = data.get("speed_source") or {}

    with connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO readings (
                panel_id,
                panel_name,
                base_url,
                checked_at,
                ok,
                upload_bps,
                download_bps,
                upload_source,
                download_source,
                error
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                panel_id(panel),
                panel.get("name") or panel.get("base_url") or "Panel",
                panel.get("base_url", ""),
                checked_at,
                1 if ok else 0,
                data.get("upload_bytes_per_second"),
                data.get("download_bytes_per_second"),
                speed_source.get("upload"),
                speed_source.get("download"),
                error,
            ),
        )


def latest_reading(
    panel: dict[str, Any],
    db_path: Path | str = DB_FILE,
) -> dict[str, Any] | None:
    init_db(db_path)
    with connect(db_path) as connection:
        row = connection.execute(
            """
            SELECT *
            FROM readings
            WHERE panel_id = ?
            ORDER BY checked_at DESC, id DESC
            LIMIT 1
            """,
            (panel_id(panel),),
        ).fetchone()

    return dict(row) if row else None


def recent_readings(
    panel: dict[str, Any],
    *,
    hours: int = 6,
    limit: int = 10000,
    db_path: Path | str = DB_FILE,
) -> list[dict[str, Any]]:
    init_db(db_path)
    since = (datetime.now() - timedelta(hours=hours)).isoformat(timespec="seconds")
    with connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT checked_at, upload_bps, download_bps
            FROM readings
            WHERE panel_id = ? AND ok = 1 AND checked_at >= ?
            ORDER BY checked_at DESC, id DESC
            LIMIT ?
            """,
            (panel_id(panel), since, limit),
        ).fetchall()

    return [dict(row) for row in reversed(rows)]

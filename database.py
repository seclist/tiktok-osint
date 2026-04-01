"""
Thread-safe SQLite persistence for investigation jobs and 24h report cache.

Uses a global lock around connections (short-lived per operation) plus WAL mode.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


CACHE_TTL_SECONDS = 24 * 60 * 60


class ReportDatabase:
    def __init__(self, db_path: Path) -> None:
        self._path = Path(db_path)
        self._lock = threading.RLock()

    def init(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("PRAGMA synchronous=NORMAL;")
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS jobs (
                        job_id TEXT PRIMARY KEY,
                        username TEXT NOT NULL,
                        status TEXT NOT NULL,
                        result_json TEXT,
                        error TEXT,
                        http_status INTEGER,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS report_cache (
                        username TEXT PRIMARY KEY,
                        report_json TEXT NOT NULL,
                        http_status INTEGER NOT NULL,
                        cached_at REAL NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_jobs_updated ON jobs(updated_at);
                    CREATE INDEX IF NOT EXISTS idx_cache_time ON report_cache(cached_at);
                    """
                )
                conn.commit()
            finally:
                conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._path), check_same_thread=False, timeout=60.0)
        conn.row_factory = sqlite3.Row
        return conn

    def normalize_username(self, username: str) -> str:
        return (username or "").strip().lstrip("@").lower()

    def create_job(self, job_id: str, username: str) -> None:
        norm = self.normalize_username(username)
        now = time.time()
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT INTO jobs (job_id, username, status, result_json, error, http_status, created_at, updated_at)
                    VALUES (?, ?, 'queued', NULL, NULL, NULL, ?, ?)
                    """,
                    (job_id, norm, now, now),
                )
                conn.commit()
            finally:
                conn.close()

    def update_job_status(self, job_id: str, status: str) -> None:
        now = time.time()
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "UPDATE jobs SET status = ?, updated_at = ? WHERE job_id = ?",
                    (status, now, job_id),
                )
                conn.commit()
            finally:
                conn.close()

    def complete_job(self, job_id: str, result: Dict[str, Any], http_status: int) -> None:
        now = time.time()
        payload = json.dumps(result, default=str)
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    UPDATE jobs
                    SET status = 'completed', result_json = ?, error = NULL, http_status = ?, updated_at = ?
                    WHERE job_id = ?
                    """,
                    (payload, http_status, now, job_id),
                )
                conn.commit()
            finally:
                conn.close()

    def fail_job(self, job_id: str, message: str) -> None:
        now = time.time()
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    UPDATE jobs
                    SET status = 'failed', error = ?, updated_at = ?
                    WHERE job_id = ?
                    """,
                    (message, now, job_id),
                )
                conn.commit()
            finally:
                conn.close()

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,))
                row = cur.fetchone()
                if not row:
                    return None
                return dict(row)
            finally:
                conn.close()

    def get_fresh_cached_report(self, username: str) -> Optional[Tuple[Dict[str, Any], int]]:
        """
        Return (report_dict, http_status) if cache row exists and is younger than CACHE_TTL_SECONDS.
        """
        norm = self.normalize_username(username)
        cutoff = time.time() - CACHE_TTL_SECONDS
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    "SELECT report_json, http_status FROM report_cache WHERE username = ? AND cached_at >= ?",
                    (norm, cutoff),
                )
                row = cur.fetchone()
                if not row:
                    return None
                return json.loads(row["report_json"]), int(row["http_status"])
            finally:
                conn.close()

    def upsert_report_cache(self, username: str, report: Dict[str, Any], http_status: int) -> None:
        norm = self.normalize_username(username)
        now = time.time()
        payload = json.dumps(report, default=str)
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT INTO report_cache (username, report_json, http_status, cached_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(username) DO UPDATE SET
                        report_json = excluded.report_json,
                        http_status = excluded.http_status,
                        cached_at = excluded.cached_at
                    """,
                    (norm, payload, http_status, now),
                )
                conn.commit()
            finally:
                conn.close()

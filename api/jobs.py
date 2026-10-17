"""Fila persistente de análises, consumida atomicamente por workers independentes."""
import json
import sqlite3
import time
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional
from uuid import uuid4

from pydantic import BaseModel


def utcnow():
    return datetime.now(timezone.utc).isoformat()


class ScanJob(BaseModel):
    job_id: str
    status: Literal["queued", "running", "completed", "failed"]
    project_name: str
    files_count: int
    created_at: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    scan_id: Optional[str] = None
    error: Optional[str] = None
    attempts: int = 0


class JobStore:
    def __init__(self, path):
        self.path = Path(path)
        self._initialized = False
        self._initialize_lock = threading.Lock()

    def initialize(self):
        if self._initialized:
            return
        with self._initialize_lock:
            if self._initialized:
                return
            self.path.parent.mkdir(parents=True, exist_ok=True)
            for attempt in range(6):
                database = sqlite3.connect(self.path, timeout=15)
                try:
                    database.execute("PRAGMA journal_mode=WAL")
                    database.execute("CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, status TEXT NOT NULL, "
                                     "project_name TEXT NOT NULL, files_count INTEGER NOT NULL, payload TEXT, "
                                     "created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT, scan_id TEXT, "
                                     "error TEXT, attempts INTEGER NOT NULL DEFAULT 0, lease_until REAL, worker_id TEXT)")
                    database.execute("CREATE INDEX IF NOT EXISTS jobs_status ON jobs(status, created_at)")
                    database.execute("CREATE TABLE IF NOT EXISTS workers (id TEXT PRIMARY KEY, updated_at REAL NOT NULL)")
                    database.commit()
                    self._initialized = True
                    return
                except sqlite3.OperationalError as error:
                    if "locked" not in str(error).lower() or attempt == 5:
                        raise
                    time.sleep(0.05 * (attempt + 1))
                finally:
                    database.close()

    @contextmanager
    def connection(self):
        self.initialize()
        database = sqlite3.connect(self.path, timeout=15)
        database.row_factory = sqlite3.Row
        try:
            yield database
            database.commit()
        finally:
            database.close()

    @staticmethod
    def _public(row):
        return ScanJob(job_id=row["id"], **{key: row[key] for key in ScanJob.model_fields if key != "job_id"}) if row else None

    def submit(self, sources, project_name, threshold, ignored=0):
        identity, created = uuid4().hex, utcnow()
        payload = json.dumps({"sources": sources, "project_name": project_name, "threshold": threshold, "ignored": ignored}, ensure_ascii=False)
        with self.connection() as database:
            database.execute("INSERT INTO jobs (id, status, project_name, files_count, payload, created_at) VALUES (?, 'queued', ?, ?, ?, ?)",
                             (identity, project_name, len(sources), payload, created))
        return self.get(identity)

    def get(self, identity):
        with self.connection() as database:
            row = database.execute("SELECT * FROM jobs WHERE id = ?", (identity,)).fetchone()
        return self._public(row)

    def claim(self, worker_id, lease_seconds=120):
        now = time.time()
        with self.connection() as database:
            database.execute("BEGIN IMMEDIATE")
            database.execute("UPDATE jobs SET status = 'failed', error = 'Worker interrompido após três tentativas.', "
                             "finished_at = ?, payload = NULL WHERE status = 'running' AND lease_until < ? AND attempts >= 3", (utcnow(), now))
            database.execute("UPDATE jobs SET status = 'queued', worker_id = NULL WHERE status = 'running' AND lease_until < ? AND attempts < 3", (now,))
            row = database.execute("SELECT * FROM jobs WHERE status = 'queued' ORDER BY created_at, rowid LIMIT 1").fetchone()
            if row is None:
                return None
            database.execute("UPDATE jobs SET status = 'running', started_at = ?, worker_id = ?, attempts = attempts + 1, lease_until = ? WHERE id = ?",
                             (utcnow(), worker_id, now + lease_seconds, row["id"]))
            return row["id"], json.loads(row["payload"])

    def complete(self, identity, worker_id, scan_id):
        with self.connection() as database:
            database.execute("UPDATE jobs SET status = 'completed', finished_at = ?, scan_id = ?, payload = NULL, lease_until = NULL "
                             "WHERE id = ? AND status = 'running' AND worker_id = ?", (utcnow(), scan_id, identity, worker_id))

    def fail(self, identity, worker_id, error):
        with self.connection() as database:
            database.execute("UPDATE jobs SET status = 'failed', finished_at = ?, error = ?, payload = NULL, lease_until = NULL "
                             "WHERE id = ? AND status = 'running' AND worker_id = ?", (utcnow(), str(error)[:1000], identity, worker_id))

    def heartbeat(self, worker_id):
        with self.connection() as database:
            database.execute("INSERT INTO workers (id, updated_at) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET updated_at = excluded.updated_at",
                             (worker_id, time.time()))
            database.execute("UPDATE jobs SET lease_until = ? WHERE status = 'running' AND worker_id = ?", (time.time() + 120, worker_id))

    def disconnect(self, worker_id):
        with self.connection() as database:
            database.execute("DELETE FROM workers WHERE id = ?", (worker_id,))

    def status(self):
        with self.connection() as database:
            counts = {row["status"]: row["total"] for row in database.execute("SELECT status, COUNT(*) AS total FROM jobs GROUP BY status")}
            workers = [row["id"] for row in database.execute("SELECT id FROM workers WHERE updated_at > ?", (time.time() - 15,))]
        return {"backend": "sqlite-durable", "active_workers": len(workers), "workers": workers,
                "counts": {status: counts.get(status, 0) for status in ("queued", "running", "completed", "failed")}}

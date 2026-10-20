"""Histórico local persistente de análises, isolado do motor de detecção."""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict
from uuid import uuid4

from engine.models import ScanResult, SemanticReview
from engine.policy import evaluate_gate


def _top_files(findings, limit: int = 5):
    """Compact file-level severity counts for the dashboard history endpoint."""
    grouped = {}
    severities = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    for finding in findings:
        path = finding.get("file_path")
        if not path:
            continue
        item = grouped.setdefault(path, {"path": path, "total_findings": 0, "summary_by_severity": {level: 0 for level in severities}})
        severity = finding.get("severity")
        if isinstance(severity, dict):
            severity = severity.get("value")
        if hasattr(severity, "value"):
            severity = severity.value
        item["total_findings"] += 1
        if severity in item["summary_by_severity"]:
            item["summary_by_severity"][severity] += 1
    return sorted(
        grouped.values(),
        key=lambda item: (
            -item["total_findings"],
            -item["summary_by_severity"]["CRITICAL"],
            -item["summary_by_severity"]["HIGH"],
            item["path"].casefold(),
        ),
    )[:limit]


class ScanStore:
    def __init__(self, path: Path):
        self.path = Path(path)

    @contextmanager
    def connection(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        database = sqlite3.connect(self.path, timeout=15)
        database.row_factory = sqlite3.Row
        try:
            database.execute("PRAGMA journal_mode=WAL")
            database.execute(
                "CREATE TABLE IF NOT EXISTS scans ("
                "id TEXT PRIMARY KEY, created_at TEXT NOT NULL, "
                "result_json TEXT NOT NULL, sources_json TEXT NOT NULL)"
            )
            database.execute(
                "CREATE TABLE IF NOT EXISTS semantic_reviews ("
                "id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, created_at TEXT NOT NULL, review_json TEXT NOT NULL)"
            )
            database.execute("CREATE INDEX IF NOT EXISTS semantic_reviews_scan ON semantic_reviews(scan_id, created_at)")
            yield database
            database.commit()
        finally:
            database.close()

    def save(self, result: ScanResult, sources: Dict[str, str], project_name: str, threshold: str) -> ScanResult:
        result.scan_id = uuid4().hex
        result.created_at = datetime.now(timezone.utc).isoformat()
        result.project_name = project_name
        result.security_gate = evaluate_gate(result, threshold)
        with self.connection() as database:
            database.execute(
                "INSERT INTO scans (id, created_at, result_json, sources_json) VALUES (?, ?, ?, ?)",
                (result.scan_id, result.created_at, result.model_dump_json(), json.dumps(sources, ensure_ascii=False)),
            )
        return result

    def get(self, scan_id: str):
        with self.connection() as database:
            row = database.execute("SELECT result_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        result = ScanResult.model_validate_json(row["result_json"])
        result.semantic_reviews = self.reviews(scan_id)
        return result

    def save_review(self, review: SemanticReview) -> SemanticReview:
        review.review_id = uuid4().hex
        review.created_at = datetime.now(timezone.utc).isoformat()
        with self.connection() as database:
            database.execute("INSERT INTO semantic_reviews (id, scan_id, created_at, review_json) VALUES (?, ?, ?, ?)",
                             (review.review_id, review.scan_id, review.created_at, review.model_dump_json()))
        return review

    def reviews(self, scan_id: str):
        with self.connection() as database:
            rows = database.execute("SELECT review_json FROM semantic_reviews WHERE scan_id = ? ORDER BY created_at DESC, rowid DESC",
                                    (scan_id,)).fetchall()
        return [SemanticReview.model_validate_json(row["review_json"]) for row in rows]

    def list(self, limit: int = 100):
        with self.connection() as database:
            rows = database.execute(
                "SELECT result_json FROM scans ORDER BY created_at DESC, rowid DESC LIMIT ?", (limit,)
            ).fetchall()
        items = []
        for row in rows:
            result = json.loads(row["result_json"])
            result["top_files"] = _top_files(result.get("findings", []))
            result["findings"] = []
            items.append(result)
        return items

    def clear(self):
        """Remove saved analyses and their semantic reviews, preserving project files."""
        with self.connection() as database:
            deleted_reviews = database.execute("DELETE FROM semantic_reviews").rowcount
            deleted_scans = database.execute("DELETE FROM scans").rowcount
        return {"deleted_scans": deleted_scans, "deleted_reviews": deleted_reviews}

    def source(self, scan_id: str, path: str):
        with self.connection() as database:
            row = database.execute("SELECT sources_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        return json.loads(row["sources_json"]).get(path)

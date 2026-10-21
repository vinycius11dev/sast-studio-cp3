"""Limpeza do histórico com backup e proteção de trabalhos em andamento."""
import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from api import main


client = TestClient(main.app)


def saved_scan():
    response = client.post("/api/v1/scan/code", json={
        "code": "eval(user_input)", "filename": "demo.py", "project_name": "Ensaio",
    })
    assert response.status_code == 200
    return response.json()


def reset():
    return client.request("DELETE", "/api/v1/scans", json={"confirmation": "CLEAR_HISTORY"})


def test_reset_requires_explicit_confirmation():
    scan = saved_scan()
    assert client.delete("/api/v1/scans").status_code == 422
    assert client.request("DELETE", "/api/v1/scans", json={"confirmation": "yes"}).status_code == 422
    assert client.get("/api/v1/scans/" + scan["scan_id"]).status_code == 200


def test_reset_backs_up_scans_sources_reviews_and_jobs(tmp_path):
    scan = saved_scan()
    with main.scan_store.connection() as database:
        database.execute("INSERT INTO semantic_reviews VALUES (?, ?, ?, ?)",
                         ("review", scan["scan_id"], scan["created_at"], '{"review":"saved"}'))
    job = main.job_store.submit({"demo.py": "eval(user_input)"}, "Ensaio", "HIGH")
    main.job_store.claim("worker-test")
    main.job_store.complete(job.job_id, "worker-test", scan["scan_id"])
    main.job_store.heartbeat("worker-test")
    original = tmp_path / "demo.py"
    original.write_text("answer = 42", encoding="utf-8")

    response = reset()
    assert response.status_code == 200
    result = response.json()
    assert {key: result[key] for key in ("deleted_scans", "deleted_reviews", "deleted_jobs")} == {
        "deleted_scans": 1, "deleted_reviews": 1, "deleted_jobs": 1,
    }
    backup = Path(result["backup_path"])
    with sqlite3.connect(backup / "scans.sqlite3") as database:
        assert database.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1
        sources = json.loads(database.execute("SELECT sources_json FROM scans").fetchone()[0])
        assert sources["demo.py"] == "eval(user_input)"
        assert database.execute("SELECT COUNT(*) FROM semantic_reviews").fetchone()[0] == 1
    with sqlite3.connect(backup / "jobs.sqlite3") as database:
        assert database.execute("SELECT scan_id FROM jobs").fetchone()[0] == scan["scan_id"]
    assert client.get("/api/v1/scans").json()["items"] == []
    assert client.get("/api/v1/scans/" + scan["scan_id"]).status_code == 404
    assert main.job_store.get(job.job_id) is None
    assert main.job_store.status()["active_workers"] == 1
    assert not any(main.job_store.status()["counts"].values())
    assert original.read_text(encoding="utf-8") == "answer = 42"


@pytest.mark.parametrize("running", [False, True])
def test_reset_refuses_active_queue_without_deleting_anything(running):
    scan = saved_scan()
    job = main.job_store.submit({"demo.py": "eval(user_input)"}, "Ensaio", "HIGH")
    if running:
        main.job_store.claim("worker-test")
    response = reset()
    assert response.status_code == 409
    assert "Aguarde" in response.json()["detail"]
    assert client.get("/api/v1/scans/" + scan["scan_id"]).status_code == 200
    assert main.job_store.get(job.job_id).status == ("running" if running else "queued")
    assert not (main.scan_store.path.parent / "history-backups").exists()


def test_failed_backup_preserves_history():
    scan = saved_scan()
    (main.scan_store.path.parent / "history-backups").write_text("blocked", encoding="utf-8")
    with pytest.raises(OSError):
        main.scan_store.clear(main.job_store)
    assert client.get("/api/v1/scans/" + scan["scan_id"]).status_code == 200


def test_empty_reset_is_idempotent_and_new_scans_still_work():
    for _ in range(2):
        assert reset().json() == {
            "deleted_scans": 0, "deleted_reviews": 0, "deleted_jobs": 0, "backup_path": None,
        }
    scan = saved_scan()
    assert client.get("/api/v1/scans/" + scan["scan_id"]).status_code == 200


def test_ai_finishing_after_reset_cannot_restore_deleted_review(monkeypatch):
    scan = saved_scan()

    def finish_review(*_args):
        main.scan_store.clear(main.job_store)
        return SimpleNamespace(scan_id=scan["scan_id"])

    monkeypatch.setattr(main.semantic_engine, "review_finding", finish_review)
    response = client.post("/api/v1/triage", json={**scan["findings"][0], "scan_id": scan["scan_id"]})
    assert response.status_code == 409
    assert client.get("/api/v1/scans").json()["items"] == []
    with main.scan_store.connection() as database:
        assert database.execute("SELECT COUNT(*) FROM semantic_reviews").fetchone()[0] == 0

import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

from fastapi.testclient import TestClient

from api import main
from api.jobs import JobStore
from api.worker import run_once


def submit(store):
    return store.submit({"sample.py": "eval(user_input)"}, "Queue demo", "HIGH")


def test_queue_survives_store_recreation(tmp_path):
    store = JobStore(tmp_path / "jobs.sqlite3")
    job = submit(store)
    reopened = JobStore(store.path).get(job.job_id)
    assert reopened.status == "queued" and reopened.files_count == 1


def test_claim_is_atomic_for_competing_workers(tmp_path):
    store = JobStore(tmp_path / "jobs.sqlite3")
    job = submit(store)
    with ThreadPoolExecutor(max_workers=6) as pool:
        claims = list(pool.map(lambda index: store.claim(f"worker-{index}"), range(6)))
    assert sum(claim is not None for claim in claims) == 1
    assert store.get(job.job_id).attempts == 1


def test_expired_lease_is_recovered_and_stale_worker_cannot_complete(tmp_path):
    store = JobStore(tmp_path / "jobs.sqlite3")
    job = submit(store)
    assert store.claim("old", lease_seconds=-1)
    assert store.claim("new")
    store.complete(job.job_id, "old", "wrong-scan")
    assert store.get(job.job_id).status == "running"
    store.complete(job.job_id, "new", "correct-scan")
    assert store.get(job.job_id).scan_id == "correct-scan"
    assert store.get(job.job_id).attempts == 2


def test_worker_processing_failure_is_recorded(tmp_path):
    store = JobStore(tmp_path / "jobs.sqlite3")
    job = submit(store)

    def broken_handler(**payload):
        raise RuntimeError("Erro controlado")

    assert run_once(store, broken_handler, "worker")
    assert store.get(job.job_id).status == "failed"
    assert "Erro controlado" in store.get(job.job_id).error


def test_worker_records_result_and_removes_source_payload(tmp_path):
    store = JobStore(tmp_path / "jobs.sqlite3")
    job = submit(store)
    assert run_once(store, lambda **payload: SimpleNamespace(scan_id="saved-scan"), "worker")
    assert store.get(job.job_id).status == "completed"
    with store.connection() as connection:
        assert connection.execute("SELECT payload FROM jobs WHERE id = ?", (job.job_id,)).fetchone()[0] is None


def test_api_queue_processes_code_with_embedded_worker():
    with TestClient(main.app) as client:
        response = client.post("/api/v1/scan/code?queued=true", json={"code": "eval(user_input)", "filename": "queued.py"})
        assert response.status_code == 202
        job = response.json()
        deadline = time.monotonic() + 10
        while job["status"] in {"queued", "running"} and time.monotonic() < deadline:
            time.sleep(0.05)
            job = client.get("/api/v1/jobs/" + job["job_id"]).json()
        assert job["status"] == "completed", job
        scan = client.get("/api/v1/scans/" + job["scan_id"]).json()
        assert scan["total_findings"] == 1
        assert scan["security_gate"]["status"] == "blocked"
        assert client.get("/api/v1/jobs/status").json()["counts"]["completed"] == 1


def test_queued_upload_validates_before_creating_job():
    with TestClient(main.app) as client:
        response = client.post("/api/v1/scan/project?queued=true", files=[("files", ("../escape.py", b"eval(x)", "text/plain"))])
        assert response.status_code == 400
        assert client.get("/api/v1/jobs/status").json()["counts"]["queued"] == 0
        assert client.get("/api/v1/jobs/not-found").status_code == 404

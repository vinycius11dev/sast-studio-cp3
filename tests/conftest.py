import pytest
from api.store import ScanStore
from api.jobs import JobStore


@pytest.fixture(autouse=True)
def isolated_scan_history(tmp_path, monkeypatch):
    """Os testes não gravam análises no histórico usado na apresentação."""
    monkeypatch.setattr("api.main.scan_store", ScanStore(tmp_path / "scans.sqlite3"))
    monkeypatch.setattr("api.main.job_store", JobStore(tmp_path / "jobs.sqlite3"))

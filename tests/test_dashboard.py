import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))
from dashboard.app import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def mock_run(tmp_path, monkeypatch):
    """Setup a fixture run directory with dummy data."""
    # We patch RUNS_DIR to point to our tmp_path
    monkeypatch.setattr("dashboard.app.RUNS_DIR", tmp_path)

    run_id = "fixture_run_123"
    run_dir = tmp_path / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    summary_data = {
        "total_bugs_processed": 5,
        "total_bugs_resolved": 4,
        "tokens_per_verified_patch": 1200.5,
        "average_time_per_verified_patch_s": 45.2,
        "percent_resolved_without_llm": 25.0,
        "total_tokens_used": 4802,
        "total_time_s": 180.8,
        "peak_memory_mb": 150.0
    }

    (run_dir / "summary.json").write_text(json.dumps(summary_data))

    return run_id, summary_data


def test_dashboard_root(client):
    """Test that the index.html is served correctly."""
    response = client.get("/")
    assert response.status_code == 200
    assert "AI Kavach" in response.text


def test_dashboard_api_success(client, mock_run):
    """Test that valid run data is served correctly via API."""
    run_id, expected_data = mock_run

    response = client.get(f"/api/runs/{run_id}/summary")

    assert response.status_code == 200
    data = response.json()
    assert data["total_bugs_processed"] == expected_data["total_bugs_processed"]
    assert data["total_bugs_resolved"] == expected_data["total_bugs_resolved"]


def test_dashboard_api_not_found(client, mock_run):
    """Test that missing run data returns 404 cleanly."""
    response = client.get("/api/runs/nonexistent_run_404/summary")

    assert response.status_code == 404
    assert response.json()["detail"] == "Run summary not found"

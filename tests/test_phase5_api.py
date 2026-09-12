"""Phase 5 API tests verifying judge-ready endpoints and multi-scenario runs."""

from starlette.testclient import TestClient
from backend.api.main import app


def test_api_providers():
    client = TestClient(app)
    res = client.get("/api/providers")
    assert res.status_code == 200
    data = res.json()
    assert "providers" in data
    assert "aws" in data["providers"]
    assert "gcp" in data["providers"]
    assert "azure" in data["providers"]
    assert data["providers"]["aws"]["supports_policy_simulation"] is True
    assert data["providers"]["gcp"]["supports_policy_simulation"] is False


def test_api_principals():
    client = TestClient(app)
    res = client.get("/api/principals")
    assert res.status_code == 200
    data = res.json()
    assert "roles" in data
    assert len(data["roles"]) > 0
    role_ids = [r["id"] for r in data["roles"]]
    assert "PaymentServiceRole" in role_ids
    assert "dependencies" in data
    assert len(data["dependencies"]) > 0


def test_api_runs_list():
    client = TestClient(app)
    res = client.get("/api/runs")
    assert res.status_code == 200
    data = res.json()
    assert "metrics" in data
    assert "runs" in data


def test_api_scenario_safety_block():
    client = TestClient(app)
    res = client.post(
        "/api/agent/run",
        json={"scenario": "safety_block", "role_id": "PaymentServiceRole"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "failed"
    assert data["stop_reason"] == "security_block"


def test_api_scenario_rollback():
    client = TestClient(app)
    res = client.post(
        "/api/agent/run",
        json={"scenario": "rollback", "role_id": "PaymentServiceRole"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "failed"
    assert data["stop_reason"] == "verification_failure_rolled_back"


def test_api_scenario_unsupported_gcp():
    client = TestClient(app)
    res = client.post(
        "/api/agent/run",
        json={"scenario": "unsupported_gcp", "role_id": "PaymentServiceRole", "provider": "gcp"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "failed"
    assert data["stop_reason"] == "unsupported_capability"


def test_api_scenario_provider_mismatch():
    client = TestClient(app)
    res = client.post(
        "/api/agent/run",
        json={"scenario": "provider_mismatch", "role_id": "PaymentServiceRole"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "failed"
    assert data["stop_reason"] == "provider_mismatch"


def test_api_scenario_stale_state():
    client = TestClient(app)
    res = client.post(
        "/api/agent/run",
        json={"scenario": "stale_state", "role_id": "PaymentServiceRole"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "completed"


def test_frontend_static_serving():
    client = TestClient(app)
    res = client.get("/")
    assert res.status_code == 200
    assert "IAM Least-Privilege Mitigator" in res.text


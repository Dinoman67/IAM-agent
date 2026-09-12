"""End-to-end integration and agent controller test suite."""

import pytest
from starlette.testclient import TestClient

from backend.agent.controller import AgentController
from backend.agent.reasoner import DeterministicReasoner
from backend.api.main import app, state_store
from backend.environment.loader import load_environment
from backend.state.store import InMemoryStateStore
from backend.tools.iam_tools import create_default_tool_registry


def test_end_to_end_agent_loop():
    """Runs the complete end-to-end autonomous IAM remediation loop."""
    env = load_environment()
    tool_registry = create_default_tool_registry(env)
    reasoner = DeterministicReasoner(target_role_id="PaymentServiceRole")
    store = InMemoryStateStore()
    events_captured = []

    controller = AgentController(
        reasoner=reasoner,
        tool_registry=tool_registry,
        state_store=store,
        event_callback=lambda e: events_captured.append(e),
    )

    goal = "Reduce excessive permissions for PaymentServiceRole without breaking required services."
    state = controller.run(goal=goal, role_id="PaymentServiceRole")

    # 1. State status
    assert state.current_phase == "COMPLETED"
    assert state.final_outcome is not None
    assert state.final_outcome.get("status") == "success"

    # 2. Tool executions occurred in right sequence
    tools_called = [c["tool_name"] for c in state.tool_calls]
    assert tools_called == [
        "get_role",
        "get_access_history",
        "find_unused_permissions",
        "simulate_policy",
        "get_service_dependencies",
        "simulate_policy",
        "apply_policy_change",
        "verify_required_access",
    ]

    # 3. Failures and replanning recorded
    assert len(state.failures) == 1
    assert state.failures[0]["failed_workflow"] == "payment_checkout"
    assert state.failures[0]["missing_permission"] == "kms:Decrypt"

    assert len(state.replans) == 1
    assert "kms:Decrypt" in state.replans[0]["retained_dependencies"]
    assert "ec2:*" in state.replans[0]["remove_permissions"]

    # 4. Verification result
    assert state.verification_result is not None
    assert state.verification_result["passed"] is True

    # 5. Audit trail completeness
    event_types = [e.event_type for e in state.audit_trail]
    expected_event_types = [
        "goal_received",
        "tool_called",
        "tool_result",
        "policy_candidate_generated",
        "simulation_started",
        "simulation_failed",
        "dependency_discovered",
        "replan_started",
        "policy_applied",
        "verification_started",
        "verification_passed",
        "final_outcome",
    ]
    for exp in expected_event_types:
        assert exp in event_types, f"Missing event type {exp} in audit trail"

    # 6. Persistence in StateStore
    saved = store.get(state.run_id)
    assert saved is not None
    assert saved.run_id == state.run_id


def test_fastapi_endpoints():
    """Verify REST API endpoints with Starlette TestClient."""
    client = TestClient(app)

    # Health check
    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "ok"

    # Run agent
    res_run = client.post(
        "/api/agent/run",
        json={
            "goal": "Reduce excessive permissions for PaymentServiceRole.",
            "role_id": "PaymentServiceRole",
        },
    )
    assert res_run.status_code == 200
    data = res_run.json()
    assert "run_id" in data
    assert data["status"] == "completed"
    assert len(data["events"]) > 0
    assert data["verification_result"]["passed"] is True

    run_id = data["run_id"]

    # Retrieve run by ID
    res_get = client.get(f"/api/agent/run/{run_id}")
    assert res_get.status_code == 200
    get_data = res_get.json()
    assert get_data["run_id"] == run_id
    assert get_data["status"] == "completed"

    # Non-existent run
    res_404 = client.get("/api/agent/run/non-existent-run")
    assert res_404.status_code == 404

"""Break-glass override: scoped human approval that can never bypass load-bearing invariants."""

from starlette.testclient import TestClient

from backend.api.main import app
from backend.environment.loader import load_environment
from backend.providers.capabilities import AWS_CAPABILITIES
from backend.security.kernel import SecurityKernel


def _halted_lowconf_run_id(client):
    r = client.post(
        "/api/agent/run",
        json={"goal": "t", "role_id": "PaymentServiceRole", "provider": "aws",
              "scenario": "lowconf", "use_mock": True, "async_run": False},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["stop_reason"] in ("human_approval_required", "high_risk")
    return data["run_id"]


def test_kernel_approval_allows_overridable_halt():
    env = load_environment()
    pruned = ["s3:GetObject", "s3:PutObject", "kms:Decrypt", "cloudwatch:PutMetricData"]
    sim = {"success": True, "proposed_permissions": pruned}
    plain = SecurityKernel(env, capabilities=AWS_CAPABILITIES).evaluate_proposal(
        role_id="PaymentServiceRole", proposed_permissions=pruned,
        planned_policy_version="v1", confidence=0.85, simulation_result=sim, provider="aws",
    )
    assert plain.decision == "escalate"  # sub-threshold confidence halts
    approved = SecurityKernel(env, capabilities=AWS_CAPABILITIES).evaluate_proposal(
        role_id="PaymentServiceRole", proposed_permissions=pruned,
        planned_policy_version="v1", confidence=0.85, simulation_result=sim, provider="aws",
        human_approval={"approved_by": "judge", "reason": "reviewed removal set"},
    )
    assert approved.decision == "allow"
    assert approved.details["human_override"]["approved_by"] == "judge"


def test_kernel_approval_never_bypasses_load_bearing():
    env = load_environment()
    # Protected-permission removal stays denied even with approval.
    bad = SecurityKernel(env, capabilities=AWS_CAPABILITIES).evaluate_proposal(
        role_id="PaymentServiceRole",
        proposed_permissions=["s3:GetObject", "kms:Decrypt"],
        planned_policy_version="v1", confidence=1.0,
        simulation_result={"success": True}, provider="aws",
        human_approval={"approved_by": "mallory", "reason": "trust me"},
    )
    assert bad.decision == "deny"
    # Privilege expansion stays denied even with approval.
    broad = ["s3:GetObject", "s3:PutObject", "kms:Decrypt", "cloudwatch:PutMetricData", "ec2:DeleteAll"]
    bad2 = SecurityKernel(env, capabilities=AWS_CAPABILITIES).evaluate_proposal(
        role_id="PaymentServiceRole", proposed_permissions=broad,
        planned_policy_version="v1", confidence=1.0,
        simulation_result={"success": True}, provider="aws",
        human_approval={"approved_by": "mallory", "reason": "trust me"},
    )
    assert bad2.decision == "deny"
    assert any("unauthorized_privilege_expansion" in c for c in bad2.reason_codes)


def test_override_approves_halted_run_end_to_end():
    client = TestClient(app)
    rid = _halted_lowconf_run_id(client)
    r = client.post("/api/agent/override", json={
        "run_id": rid, "approved_by": "demo-judge", "reason": "reviewed low-risk removal set"})
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "completed"
    assert data["stop_reason"] == "verified_success"
    assert set(data["policy_diff"]["removed"]) == {"ec2:*", "iam:*", "dynamodb:*"}
    events = [e["event_type"] for e in data["events"]]
    assert "security_check" in events and "policy_applied" in events and "verification_passed" in events


def test_override_validates_input():
    client = TestClient(app)
    rid = _halted_lowconf_run_id(client)
    assert client.post("/api/agent/override",
                       json={"run_id": rid, "approved_by": "", "reason": "x"}).status_code == 400
    assert client.post("/api/agent/override",
                       json={"run_id": "run-doesnotexist", "approved_by": "a", "reason": "b"}).status_code == 404
    assert client.post("/api/agent/override",
                       json={"run_id": rid, "approved_by": "a" * 121, "reason": "b"}).status_code == 400


def test_override_refuses_unoverridable_and_applied():
    client = TestClient(app)
    # safety_block records no proposal -> 400 (nothing approvable exists)
    sb = client.post("/api/agent/run",
                     json={"goal": "t", "role_id": "PaymentServiceRole", "provider": "aws",
                           "scenario": "safety_block", "use_mock": True, "async_run": False}).json()
    assert sb["stop_reason"] == "security_block"
    r = client.post("/api/agent/override",
                    json={"run_id": sb["run_id"], "approved_by": "mallory", "reason": "trust me"})
    assert r.status_code == 400
    # completed runs cannot be overridden
    ok = client.post("/api/agent/run",
                     json={"goal": "t", "role_id": "PaymentServiceRole", "provider": "aws",
                           "scenario": "aws", "use_mock": True, "async_run": False}).json()
    assert ok["status"] == "completed"
    r2 = client.post("/api/agent/override",
                     json={"run_id": ok["run_id"], "approved_by": "a", "reason": "b"})
    assert r2.status_code == 400


def test_override_refused_path_records_refusal():
    """A fabricated halted run whose proposal violates load-bearing rules refuses."""
    from backend.api.main import state_store
    from backend.state.models import AgentState

    st = AgentState(goal="t", current_role="PaymentServiceRole", provider="aws", current_phase="FAILED")
    st.stop_reason = "security_block"
    st.candidate_policy_changes = [{
        "role_id": "PaymentServiceRole",
        "remove_permissions": ["iam:CreateRole"],
        "proposed_permissions": ["s3:GetObject", "kms:Decrypt"],
        "reason": "unsafe",
    }]
    state_store.save(st)
    client = TestClient(app)
    r = client.post("/api/agent/override",
                    json={"run_id": st.run_id, "approved_by": "mallory", "reason": "trust me"})
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "failed"
    assert data["stop_reason"] == "override_refused"
    assert state_store.get(st.run_id).stop_reason == "security_block"  # original untouched

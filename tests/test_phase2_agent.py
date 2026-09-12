"""Tests for Phase 2 Agent behavior, structured decisions, budgeting, and mock reasoning."""

import pytest

from backend.agent.budgets import AgentBudget, BudgetTracker
from backend.agent.controller import AgentController
from backend.agent.decisions import AgentDecision, Decision
from backend.agent.planner import AgentPlan
from backend.agent.reasoner import LLMReasoner, MockReasoner
from backend.environment.loader import load_environment
from backend.state.models import AgentState
from backend.state.store import InMemoryStateStore, JSONFileStateStore, SQLiteStateStore
from backend.tools.iam_tools import create_extended_tool_registry


def test_mock_reasoner_valid_tool_selection():
    """Verify MockReasoner drives the controller deterministically."""
    env = load_environment()
    tools = create_extended_tool_registry(env)
    decisions = [
        AgentDecision(
            decision_type="tool_call",
            tool_name="get_role",
            arguments={"role_id": "PaymentServiceRole"},
            reason="Inspect role",
        ),
        AgentDecision(
            decision_type="tool_call",
            tool_name="verify_required_access",
            arguments={"role_id": "PaymentServiceRole"},
            reason="Verify initial",
        ),
        AgentDecision(
            decision_type="complete",
            reason="Finished test sequence",
            confidence=1.0,
        ),
    ]
    reasoner = MockReasoner(decisions)
    controller = AgentController(reasoner=reasoner, tool_registry=tools, environment=env)
    state = controller.run(goal="Test mock reasoner", role_id="PaymentServiceRole")

    assert state.current_phase in ["COMPLETED", "FAILED"]
    tool_names = [c["tool_name"] for c in state.tool_calls]
    assert tool_names == ["get_role", "verify_required_access"]


def test_invalid_tool_call_rejected_safely():
    """Unregistered or invalid tool calls are caught gracefully by the registry/controller."""
    env = load_environment()
    tools = create_extended_tool_registry(env)
    decisions = [
        AgentDecision(
            decision_type="tool_call",
            tool_name="malicious_or_nonexistent_tool",
            arguments={"cmd": "rm -rf /"},
            reason="Attempting illegal action",
        ),
        AgentDecision(
            decision_type="abort",
            reason="Aborting after rejected tool",
        ),
    ]
    reasoner = MockReasoner(decisions)
    controller = AgentController(reasoner=reasoner, tool_registry=tools, environment=env)
    state = controller.run(goal="Test invalid tool safety", role_id="PaymentServiceRole")

    assert len(state.tool_results) == 1
    assert state.tool_results[0]["success"] is False
    assert "not registered" in state.tool_results[0]["error"]
    assert state.current_phase == "FAILED"


def test_malformed_llm_output_handled():
    """LLM response extractor properly parses JSON from code blocks and handles malformed strings."""
    # 1. Clean JSON extraction
    raw = '```json\n{"decision_type": "tool_call", "tool_name": "get_role", "arguments": {"role_id": "r1"}, "reason": "test", "confidence": 0.9}\n```'
    extracted = LLMReasoner._extract_json(raw)
    assert extracted["decision_type"] == "tool_call"
    assert extracted["tool_name"] == "get_role"

    # 2. Raw JSON without fences
    raw2 = '{"decision_type": "complete", "reason": "done", "confidence": 1.0}'
    extracted2 = LLMReasoner._extract_json(raw2)
    assert extracted2["decision_type"] == "complete"

    # 3. Invalid JSON raises JSONDecodeError gracefully
    with pytest.raises(Exception):
        LLMReasoner._extract_json("not valid json at all")


def test_bounded_iteration_budget_exhaustion():
    """Agent must stop safely when MAX_ITERATIONS limit is reached."""
    env = load_environment()
    tools = create_extended_tool_registry(env)
    # Infinitely loop tool calls
    infinite_decisions = [
        AgentDecision(
            decision_type="tool_call",
            tool_name="get_access_history",
            arguments={"role_id": "PaymentServiceRole"},
            reason="Looping inspect",
        )
        for _ in range(50)
    ]
    reasoner = MockReasoner(infinite_decisions)
    budget = AgentBudget(max_iterations=3, max_tool_calls=50)
    controller = AgentController(
        reasoner=reasoner,
        tool_registry=tools,
        budget=budget,
        environment=env,
    )

    state = controller.run(goal="Test loop limit", role_id="PaymentServiceRole", max_steps=100)

    assert state.current_phase == "FAILED"
    assert state.stop_reason == "budget_exhausted"
    assert "MAX_ITERATIONS limit reached" in state.final_outcome["message"]
    assert len(state.tool_calls) <= 3


def test_bounded_replanning_budget_exhaustion():
    """Agent must stop safely when MAX_REPLANS limit is reached."""
    env = load_environment()
    tools = create_extended_tool_registry(env)
    replan_decisions = [
        AgentDecision(decision_type="replan", reason=f"Replan #{i}")
        for i in range(10)
    ]
    reasoner = MockReasoner(replan_decisions)
    budget = AgentBudget(max_iterations=50, max_replans=2)
    controller = AgentController(
        reasoner=reasoner,
        tool_registry=tools,
        budget=budget,
        environment=env,
    )

    state = controller.run(goal="Test replan budget", role_id="PaymentServiceRole")

    assert state.current_phase == "FAILED"
    assert state.stop_reason == "budget_exhausted"
    assert "MAX_REPLANS limit reached" in state.final_outcome["message"]


def test_bounded_runtime_seconds_exhaustion():
    """Budget tracker triggers exhaustion on runtime exceeded."""
    tracker = BudgetTracker(AgentBudget(max_runtime_seconds=0.001))
    import time
    time.sleep(0.01)
    exhaustion = tracker.check_exhausted()
    assert exhaustion is not None
    assert "MAX_RUNTIME_SECONDS exceeded" in exhaustion


def test_terminal_success_stops_agent():
    """Once complete is returned and verification passed, agent stops immediately."""
    env = load_environment()
    tools = create_extended_tool_registry(env)
    # Simulate first a passed verification then complete
    decisions = [
        AgentDecision(
            decision_type="tool_call",
            tool_name="verify_required_access",
            arguments={"role_id": "PaymentServiceRole"},
            reason="Verify access",
        ),
        AgentDecision(
            decision_type="complete",
            reason="Verified and finished",
            confidence=1.0,
        ),
        AgentDecision(
            decision_type="tool_call",
            tool_name="get_role",
            arguments={"role_id": "PaymentServiceRole"},
            reason="This should never be called",
        ),
    ]
    reasoner = MockReasoner(decisions)
    controller = AgentController(reasoner=reasoner, tool_registry=tools, environment=env)
    state = controller.run(goal="Test terminal stop", role_id="PaymentServiceRole")

    assert len(state.tool_calls) == 1
    assert state.tool_calls[0]["tool_name"] == "verify_required_access"


def test_agent_plan_lifecycle():
    """AgentPlan tracks objective, assumptions, and version increments on revision."""
    plan = AgentPlan(objective="Secure Payment Role")
    assert plan.version == 1
    assert plan.status == "draft"

    plan.mark_active()
    assert plan.status == "active"

    plan.revise(
        replan_reason="Dependency on KMS discovered",
        new_candidate_changes=[{"remove": ["ec2:*"]}],
    )
    assert plan.version == 2
    assert plan.status == "replanning"
    assert plan.replan_reason == "Dependency on KMS discovered"

    plan.mark_verified()
    assert plan.status == "verified"


def test_context_management_summary():
    """LLM reasoner context summary retains goal, role, active permissions, and recent activity."""
    reasoner = LLMReasoner(mock_fallback=True)
    state = AgentState(
        goal="Test context size",
        current_role="PaymentServiceRole",
        observed_evidence={
            "role": {"active_permissions": ["s3:GetObject", "ec2:*"]},
            "unused_permissions": ["ec2:*"],
        },
    )
    summary = reasoner._build_context_summary(
        state=state,
        available_tools=[{"name": "get_role", "description": "Fetch role"}],
        evidence=state.observed_evidence,
        history=[],
    )

    assert "Test context size" in summary
    assert "PaymentServiceRole" in summary
    assert "s3:GetObject" in summary
    assert "ec2:*" in summary
    assert "AVAILABLE TOOLS:" in summary


def test_persistent_state_stores(tmp_path):
    """Test JSON and SQLite state stores serialize and deserialize AgentState accurately."""
    state = AgentState(
        goal="Persistence test",
        current_role="PaymentServiceRole",
        telemetry={"iterations": "5/20"},
    )

    # 1. JSON file store
    json_dir = tmp_path / "runs"
    json_store = JSONFileStateStore(directory=json_dir)
    json_store.save(state)

    retrieved_json = json_store.get(state.run_id)
    assert retrieved_json is not None
    assert retrieved_json.run_id == state.run_id
    assert retrieved_json.telemetry["iterations"] == "5/20"
    assert len(json_store.list_all()) == 1

    # 2. SQLite store
    db_file = tmp_path / "test_iam.db"
    sqlite_store = SQLiteStateStore(db_path=str(db_file))
    sqlite_store.save(state)

    retrieved_sqlite = sqlite_store.get(state.run_id)
    assert retrieved_sqlite is not None
    assert retrieved_sqlite.run_id == state.run_id
    assert retrieved_sqlite.telemetry["iterations"] == "5/20"
    assert len(sqlite_store.list_all()) == 1


def test_controller_automated_rollback_on_failed_verification():
    """If verification fails after policy mutation, controller invokes rollback."""
    env = load_environment()
    tools = create_extended_tool_registry(env)

    # Decisions: apply broken policy (removing required KMS without check), then verify -> fails -> triggers rollback
    decisions = [
        AgentDecision(
            decision_type="tool_call",
            tool_name="get_role",
            arguments={"role_id": "PaymentServiceRole"},
            reason="Inspect role",
        ),
        AgentDecision(
            decision_type="tool_call",
            tool_name="apply_policy_change",
            arguments={
                "role_id": "PaymentServiceRole",
                "remove_permissions": ["kms:Decrypt"],
                "reason": "Faulty removal",
            },
            reason="Apply faulty change without simulation",
        ),
        AgentDecision(
            decision_type="tool_call",
            tool_name="verify_required_access",
            arguments={"role_id": "PaymentServiceRole"},
            reason="Verify",
        ),
        AgentDecision(
            decision_type="abort",
            reason="Aborting after verification failure",
        ),
    ]
    reasoner = MockReasoner(decisions)
    # Use controller without pre-execution kernel deny to test post-apply verification rollback
    controller = AgentController(reasoner=reasoner, tool_registry=tools, environment=env)
    state = controller.run(goal="Test rollback on verification failure", role_id="PaymentServiceRole")

    rollback_events = [e for e in state.audit_trail if e.event_type == "rollback"]
    assert len(rollback_events) >= 1
    # Check that role was rolled back to v1
    role = env.get_role("PaymentServiceRole")
    assert role.current_version == "v1"


def test_stop_condition_safe_no_change_required():
    """If no changes were proposed or needed and verification passes, stop reason is safe_no_change_required."""
    env = load_environment()
    # Set the role to already be least-privilege
    env.apply_policy_version(
        "PaymentServiceRole",
        ["s3:GetObject", "s3:PutObject", "kms:Decrypt", "cloudwatch:PutMetricData"],
        "Pre-mitigated state",
    )
    tools = create_extended_tool_registry(env)
    decisions = [
        AgentDecision(
            decision_type="tool_call",
            tool_name="verify_required_access",
            arguments={"role_id": "PaymentServiceRole"},
            reason="Verify existing access without proposing modifications",
        ),
        AgentDecision(
            decision_type="complete",
            reason="Role is already operating as intended",
            confidence=1.0,
        ),
    ]
    reasoner = MockReasoner(decisions)
    controller = AgentController(reasoner=reasoner, tool_registry=tools, environment=env)
    state = controller.run(goal="Check existing role status", role_id="PaymentServiceRole")

    assert state.current_phase == "COMPLETED"
    assert state.stop_reason == "safe_no_change_required"
    assert state.final_outcome["status"] == "success"


def test_stop_condition_unsupported_capability():
    """If agent or provider encounters an unsupported capability, stop reason is unsupported_capability."""
    env = load_environment()
    tools = create_extended_tool_registry(env)
    decisions = [
        AgentDecision(
            decision_type="escalate",
            reason="Escalating due to unsupported_capability: provider lacks pre-commit simulation",
            confidence=0.9,
            metadata={"unsupported_capability": "simulation"},
        ),
    ]
    reasoner = MockReasoner(decisions)
    controller = AgentController(reasoner=reasoner, tool_registry=tools, environment=env)
    state = controller.run(goal="Test unsupported capability stop", role_id="PaymentServiceRole")

    assert state.current_phase == "FAILED"
    assert state.stop_reason == "unsupported_capability"


def test_stale_state_triggers_refresh_and_replan_event():
    """Security Kernel detects stale version, controller refreshes state and records adapt/replan."""
    env = load_environment()
    tools = create_extended_tool_registry(env)

    # First update the role externally so planned version 'v1' is stale (now 'v2')
    env.apply_policy_version("PaymentServiceRole", ["s3:GetObject", "kms:Decrypt"], "External change")

    decisions = [
        AgentDecision(
            decision_type="tool_call",
            tool_name="apply_policy_change",
            arguments={
                "role_id": "PaymentServiceRole",
                "new_permissions": ["s3:GetObject"],
                "reason": "Applying on stale assumption",
            },
            reason="Attempting apply",
            confidence=0.95,
        ),
        AgentDecision(
            decision_type="abort",
            reason="Aborting after replan",
        ),
    ]
    reasoner = MockReasoner(decisions)
    controller = AgentController(reasoner=reasoner, tool_registry=tools, environment=env)
    state = controller.run(goal="Test stale state recovery", role_id="PaymentServiceRole")

    # Verify stale state denial and adapt event occurred
    adapt_events = [e for e in state.audit_trail if e.event_type == "adapt" and "stale_state" in e.details]
    assert len(adapt_events) >= 1
    assert adapt_events[0].details.get("refreshed_version") == "v2"


def test_llm_reasoner_http_mocked_success(monkeypatch):
    """Verify LLMReasoner parses structured JSON returned over HTTP from model endpoint."""
    import httpx
    fake_json_response = {
        "choices": [
            {
                "message": {
                    "content": '{"decision_type": "tool_call", "tool_name": "inspect_role", "arguments": {"role_id": "PaymentServiceRole"}, "reason": "Inspecting role via LLM", "confidence": 0.95}'
                }
            }
        ]
    }

    class FakeResponse:
        status_code = 200
        def raise_for_status(self):
            pass
        def json(self):
            return fake_json_response

    def fake_post(*args, **kwargs):
        return FakeResponse()

    monkeypatch.setattr(httpx.Client, "post", fake_post)

    reasoner = LLMReasoner(api_key="test-mock-key", mock_fallback=False)
    state = AgentState(goal="Test LLM reasoner HTTP", current_role="PaymentServiceRole")

    decision = reasoner.decide(state=state)
    assert decision.decision_type == "tool_call"
    assert decision.tool_name == "inspect_role"
    assert decision.arguments == {"role_id": "PaymentServiceRole"}
    assert decision.confidence == 0.95


def test_all_phase2_tools_in_registry():
    """Verify all 12 Phase 2 tool specifications are registered in extended registry."""
    env = load_environment()
    registry = create_extended_tool_registry(env)
    registered_names = set(t["name"] for t in registry.list_tools())

    required_phase2_tools = {
        "inspect_role",
        "inspect_policy",
        "find_unused_permissions",
        "analyze_policy",
        "get_service_dependencies",
        "simulate_policy_change",
        "compute_policy_diff",
        "verify_required_access",
        "check_security_invariants",
        "apply_policy_change",
        "rollback_policy_change",
        "get_provider_capabilities",
    }

    for tool_name in required_phase2_tools:
        assert tool_name in registered_names, f"Missing tool in registry: {tool_name}"



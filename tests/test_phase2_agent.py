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


"""Tests for interface contracts, protocols, and schema validation."""

import pytest
from pydantic import ValidationError

from backend.agent.reasoner import Decision, DeterministicReasoner, Reasoner
from backend.environment.loader import load_environment
from backend.models.schemas import (
    AccessLog,
    PolicyVersion,
    Principal,
    Role,
    SimulationResult,
    VerificationResult,
)
from backend.state.models import AgentState, AuditEvent
from backend.state.store import InMemoryStateStore, StateStore
from backend.tools.base import BaseTool, ToolResult
from backend.tools.iam_tools import (
    GetRoleTool,
    create_default_tool_registry,
)
from backend.tools.registry import ToolRegistry


def test_reasoner_protocol_compliance() -> None:
    """Ensure DeterministicReasoner complies with the Reasoner Protocol."""
    reasoner = DeterministicReasoner()
    assert isinstance(reasoner, Reasoner)
    state = AgentState(goal="Test goal", current_role="PaymentServiceRole")
    decision = reasoner.decide(state)
    assert isinstance(decision, Decision)
    assert decision.action_type in ["call_tool", "complete", "fail"]


def test_state_store_protocol_compliance() -> None:
    """Ensure InMemoryStateStore satisfies the StateStore Protocol."""
    store = InMemoryStateStore()
    assert isinstance(store, StateStore)

    state = AgentState(goal="Protocol test", current_role="TestRole")
    store.save(state)

    retrieved = store.get(state.run_id)
    assert retrieved is not None
    assert retrieved.run_id == state.run_id
    assert retrieved.goal == "Protocol test"
    assert len(store.list_all()) == 1


def test_tool_contract_validation_error() -> None:
    """Ensure tool execution catches invalid arguments and returns structured failure."""
    env = load_environment()
    tool = GetRoleTool(env)
    assert isinstance(tool, BaseTool)

    # Missing required argument 'role_id'
    result = tool.run()
    assert isinstance(result, ToolResult)
    assert result.success is False
    assert "Invalid arguments" in result.error
    assert result.metadata.get("validation_error") is True


def test_registry_unregistered_tool() -> None:
    """Ensure calling an unregistered tool returns clean error."""
    registry = ToolRegistry()
    result = registry.execute("non_existent_tool", {"foo": "bar"})
    assert isinstance(result, ToolResult)
    assert result.success is False
    assert "is not registered" in result.error


def test_pydantic_schema_invariants() -> None:
    """Verify that core data models properly enforce types."""
    # Valid PolicyVersion
    pv = PolicyVersion(version_id="v1", permissions=["s3:GetObject"])
    assert pv.version_id == "v1"
    assert pv.is_active is True

    # Missing required fields in AccessLog should raise ValidationError
    with pytest.raises(ValidationError):
        AccessLog(id="log-1", principal_id="p1")  # missing role_id, action, resource, timestamp

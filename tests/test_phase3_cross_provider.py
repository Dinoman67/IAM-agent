"""Phase 3 Tests: Cross-Provider High-Level Scenarios and Telemetry Verification."""

import pytest

from backend.agent.controller import AgentController
from backend.agent.decisions import AgentDecision
from backend.agent.reasoner import DeterministicReasoner
from backend.environment.loader import load_environment
from backend.models.iam import CommonPolicy
from backend.providers.adapters import AWSProviderAdapter, AzureProviderAdapter, GCPProviderAdapter
from backend.providers.capabilities import AWS_CAPABILITIES, AZURE_CAPABILITIES, GCP_CAPABILITIES
from backend.security.kernel import SecurityKernel
from backend.tools.iam_tools import create_extended_tool_registry


class MockSequenceReasoner:
    """Mock reasoner returning explicit sequential decisions for test scenarios."""

    def __init__(self, decisions):
        self.decisions = list(decisions)
        self.call_count = 0

    def decide(self, state, **kwargs):
        if self.call_count < len(self.decisions):
            d = self.decisions[self.call_count]
            self.call_count += 1
            return d
        return AgentDecision(decision_type="abort", reason="Sequence exhausted")


def test_cross_provider_scenario_aws_complete():
    """End-to-end scenario on AWS: completes full closed loop with provider-tagged audit trail."""
    env = load_environment()
    tools = create_extended_tool_registry(env)
    reasoner = DeterministicReasoner(target_role_id="PaymentServiceRole")

    controller = AgentController(
        reasoner=reasoner,
        tool_registry=tools,
        environment=env,
        provider="aws",
    )

    state = controller.run(
        goal="Make PaymentServiceRole least privilege while preserving payment workflow.",
        role_id="PaymentServiceRole",
        provider="aws",
    )

    assert state.current_phase == "COMPLETED"
    assert state.stop_reason == "verified_success"
    assert state.provider == "aws"

    # Assert every significant audit event records provider="aws"
    assert len(state.audit_trail) >= 8
    for evt in state.audit_trail:
        assert evt.provider == "aws"
        assert evt.run_id == state.run_id

    # Verify policy diff has both common and AWS-specific representation
    assert state.policy_diff is not None
    p_diff = state.policy_diff
    assert p_diff["provider"] == "aws"
    assert "AllowRequestedActions" in p_diff["provider_diff"]["statement_id"]
    assert "ec2:*" in p_diff["removed"]
    assert "kms:Decrypt" in p_diff["kept"]


def test_cross_provider_scenario_gcp_safe_unsupported_escalation():
    """End-to-end scenario on GCP: attempts simulation, detects unsupported capability, escalates truthfully."""
    env = load_environment()
    tools = create_extended_tool_registry(env)

    # Decisions simulating an agent trying to inspect role, propose change, and simulate
    decisions = [
        AgentDecision(
            decision_type="tool_call",
            tool_name="get_role",
            arguments={"role_id": "PaymentServiceRole"},
            reason="Observing role",
        ),
        AgentDecision(
            decision_type="tool_call",
            tool_name="simulate_policy_change",
            arguments={"role_id": "PaymentServiceRole", "remove_permissions": ["ec2:*"]},
            reason="Simulating policy on GCP",
        ),
    ]
    reasoner = MockSequenceReasoner(decisions)

    controller = AgentController(
        reasoner=reasoner,
        tool_registry=tools,
        environment=env,
        provider="gcp",
    )

    state = controller.run(
        goal="Mitigate excessive permissions for GCP storage role.",
        role_id="PaymentServiceRole",
        provider="gcp",
    )

    # Must escalate due to unsupported capability, NOT fake success
    assert state.current_phase == "FAILED"
    assert state.stop_reason == "unsupported_capability"
    assert state.provider == "gcp"

    # Verify escalation audit event
    escalate_events = [e for e in state.audit_trail if e.event_type == "escalate"]
    assert len(escalate_events) >= 1
    esc_evt = escalate_events[0]
    assert esc_evt.provider == "gcp"
    assert "simulate_policy" in esc_evt.operation or "simulate" in esc_evt.summary
    assert "Local GCP simulation is not implemented" in str(esc_evt.details)


def test_cross_provider_scenario_azure_safe_unsupported_escalation():
    """End-to-end scenario on Azure: attempts simulation, detects unsupported capability, escalates truthfully."""
    env = load_environment()
    tools = create_extended_tool_registry(env)

    decisions = [
        AgentDecision(
            decision_type="tool_call",
            tool_name="get_role",
            arguments={"role_id": "PaymentServiceRole"},
            reason="Observing role",
        ),
        AgentDecision(
            decision_type="tool_call",
            tool_name="simulate_change",
            arguments={"role_id": "PaymentServiceRole", "proposed_permissions": ["s3:GetObject"]},
            reason="Attempting simulation on Azure",
        ),
    ]
    reasoner = MockSequenceReasoner(decisions)

    controller = AgentController(
        reasoner=reasoner,
        tool_registry=tools,
        environment=env,
        provider="azure",
    )

    state = controller.run(
        goal="Mitigate excessive permissions for Azure Contributor role.",
        role_id="PaymentServiceRole",
        provider="azure",
    )

    assert state.current_phase == "FAILED"
    assert state.stop_reason == "unsupported_capability"
    assert state.provider == "azure"

    escalate_events = [e for e in state.audit_trail if e.event_type == "escalate"]
    assert len(escalate_events) >= 1
    assert escalate_events[0].provider == "azure"
    assert "azure" in escalate_events[0].summary.lower()


def test_cross_provider_mismatch_scenario_blocked_by_kernel():
    """Security Kernel denies cross-provider proposal and records provider mismatch audit event."""
    env = load_environment()
    tools = create_extended_tool_registry(env)

    # Proposal with provider="azure" sent to AWS controller/kernel
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
                "new_permissions": ["s3:GetObject", "kms:Decrypt"],
                "reason": "Applying foreign policy",
            },
            reason="Attempting apply",
            metadata={"candidate_phase": "initial_proposal"},
        ),
    ]
    reasoner = MockSequenceReasoner(decisions)

    # Controller configured with AWS capabilities
    controller = AgentController(
        reasoner=reasoner,
        tool_registry=tools,
        environment=env,
        provider="aws",
    )

    # Set security kernel to explicitly check for Azure mismatch
    class MismatchKernel(SecurityKernel):
        def evaluate_proposal(self, *args, **kwargs):
            res = super().evaluate_proposal(*args, **kwargs)
            # Inject foreign provider
            return super().evaluate_proposal(*args, **{**kwargs, "provider": "azure"})

    controller.security_kernel = MismatchKernel(env, capabilities=AWS_CAPABILITIES)

    state = controller.run(
        goal="Attempt cross-provider mutation",
        role_id="PaymentServiceRole",
        provider="aws",
    )

    assert state.current_phase == "FAILED"
    assert state.stop_reason == "provider_mismatch"

    mismatch_events = [e for e in state.audit_trail if e.event_type == "provider_mismatch"]
    assert len(mismatch_events) >= 1
    assert "provider_mismatch" in mismatch_events[0].details.get("details", {}).get("provider_mismatch", {}).get("reason", "").lower() or any("provider_mismatch" in c for c in mismatch_events[0].details.get("reason_codes", []))

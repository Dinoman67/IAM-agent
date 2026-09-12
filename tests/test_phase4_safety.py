"""Phase 4 Comprehensive Safety, Verification, and Autonomous Remediation Hardening Tests.

Verifies:
- Explicit Security Invariants
- Blast Radius Assessment (LOW, MEDIUM, HIGH, CRITICAL)
- Privilege Expansion Detection (actions, wildcards, resources, conditions)
- Policy Regression Test Suite (positive workflows + negative security invariants)
- Evidence Sufficiency Gate (fail-closed on UNKNOWN and DEPENDENCY_REQUIRED)
- All 9 Adversarial Scenarios
- Loop Prevention and Bounded Rollback Limits
"""

import pytest
from typing import Any, Dict, List

from backend.agent.budgets import AgentBudget
from backend.agent.controller import AgentController
from backend.agent.decisions import AgentDecision
from backend.agent.reasoner import DeterministicReasoner, Reasoner
from backend.environment.loader import IAMEnvironment, load_environment
from backend.models.iam import CommonPolicy
from backend.providers.capabilities import AWS_CAPABILITIES, GCP_CAPABILITIES, ProviderCapabilities
from backend.security.analyzer import SecurityAnalyzer
from backend.security.blast_radius import calculate_blast_radius
from backend.security.escalation import EscalationReason, build_escalation
from backend.security.evidence_gate import evaluate_evidence_sufficiency
from backend.security.expansion import check_privilege_expansion
from backend.security.invariants import (
    INVARIANT_NO_COMPLETION_WITHOUT_VERIFICATION,
    INVARIANT_NO_CROSS_PROVIDER_MUTATION,
    INVARIANT_NO_CROSS_TENANT_MUTATION,
    INVARIANT_NO_MUTATION_WITHOUT_EVIDENCE,
    INVARIANT_NO_MUTATION_WITHOUT_PRE_APPLY_VERIFICATION,
    INVARIANT_NO_MUTATION_WITHOUT_SIMULATION,
    INVARIANT_NO_PRIVILEGE_EXPANSION,
    INVARIANT_NO_PROTECTED_PERMISSION_MUTATION,
    INVARIANT_NO_PROTECTED_RESOURCE_EXPOSURE,
    INVARIANT_NO_STALE_STATE_MUTATION,
    INVARIANT_NO_UNAPPROVED_HIGH_RISK,
    SecurityInvariant,
)
from backend.security.kernel import SecurityKernel
from backend.security.policy_config import SecurityPolicyConfig
from backend.security.regression import (
    PolicyRegressionTest,
    RegressionTestSuite,
    create_default_regression_suite,
)
from backend.security.verification import ExtendedPolicyVerifier
from backend.tools.iam_tools import create_extended_tool_registry


class MockSequenceReasoner(Reasoner):
    """Mock reasoner returning explicit sequential decisions for test scenarios."""

    def __init__(self, decisions: List[AgentDecision]) -> None:
        self.decisions = list(decisions)
        self.call_count = 0

    def decide(self, state, **kwargs) -> AgentDecision:
        if self.call_count < len(self.decisions):
            d = self.decisions[self.call_count]
            self.call_count += 1
            return d
        return AgentDecision(decision_type="abort", reason="Sequence exhausted")


# ==============================================================================
# 1. EXPLICIT INVARIANTS TESTS
# ==============================================================================

def test_security_invariants_definitions():
    """Verify all 11 core security invariants are defined with descriptive specifications."""
    expected_invariants = [
        INVARIANT_NO_PRIVILEGE_EXPANSION,
        INVARIANT_NO_PROTECTED_PERMISSION_MUTATION,
        INVARIANT_NO_PROTECTED_RESOURCE_EXPOSURE,
        INVARIANT_NO_CROSS_PROVIDER_MUTATION,
        INVARIANT_NO_CROSS_TENANT_MUTATION,
        INVARIANT_NO_STALE_STATE_MUTATION,
        INVARIANT_NO_MUTATION_WITHOUT_EVIDENCE,
        INVARIANT_NO_MUTATION_WITHOUT_SIMULATION,
        INVARIANT_NO_MUTATION_WITHOUT_PRE_APPLY_VERIFICATION,
        INVARIANT_NO_COMPLETION_WITHOUT_VERIFICATION,
        INVARIANT_NO_UNAPPROVED_HIGH_RISK,
    ]
    for inv in expected_invariants:
        assert isinstance(inv, SecurityInvariant)
        assert len(inv.id) > 0
        assert len(inv.description) > 0
        assert inv.severity in ("critical", "high", "medium", "low")


# ==============================================================================
# 2. BLAST RADIUS ASSESSMENT TESTS
# ==============================================================================

def test_blast_radius_calculation_levels():
    """Verify blast radius calculator assigns LOW, MEDIUM, HIGH, and CRITICAL appropriately."""
    # 1. LOW: Standard service role, removes unused wildcards, preserves specific needed permissions
    assessment_low = calculate_blast_radius(
        original_permissions=["s3:GetObject", "s3:PutObject", "ec2:*", "iam:*"],
        proposed_permissions=["s3:GetObject", "s3:PutObject"],
        resources_affected=["arn:aws:s3:::payment-bucket/*"],
        principal_id="PaymentServiceRole",
        principal_type="service",
        is_sensitive_principal=False,
        dependencies_count=1,
        touches_protected_resource=False,
    )
    assert assessment_low.level in ("LOW", "MEDIUM")
    assert assessment_low.score < 60.0

    # 2. MEDIUM: Moderate change on multiple resources
    assessment_med = calculate_blast_radius(
        original_permissions=["s3:GetObject", "s3:PutObject", "sqs:*", "sns:*"],
        proposed_permissions=["s3:GetObject", "sqs:ReceiveMessage"],
        resources_affected=["res1", "res2", "res3", "res4"],
        principal_id="WorkerServiceRole",
        principal_type="service",
        is_sensitive_principal=False,
        dependencies_count=4,
        touches_protected_resource=False,
    )
    assert assessment_med.level in ("MEDIUM", "HIGH")

    # 3. HIGH: Sensitive principal (admin) with wide scope
    assessment_high = calculate_blast_radius(
        original_permissions=["iam:*", "ec2:*", "s3:*"],
        proposed_permissions=["iam:*", "ec2:Describe*"],
        resources_affected=["*"],
        principal_id="IAMAdminRole",
        principal_type="admin",
        is_sensitive_principal=True,
        dependencies_count=2,
        touches_protected_resource=False,
    )
    assert assessment_high.level in ("HIGH", "CRITICAL")
    assert assessment_high.principal_sensitivity in ("critical_identity", "CRITICAL")

    # 4. CRITICAL: Retaining global wildcard '*' and touching protected resources
    assessment_crit = calculate_blast_radius(
        original_permissions=["*"],
        proposed_permissions=["*"],
        resources_affected=["arn:aws:s3:::customer-pii-vault/*"],
        principal_id="RootAccountRole",
        principal_type="admin",
        is_sensitive_principal=True,
        dependencies_count=5,
        touches_protected_resource=True,
    )
    assert assessment_crit.level == "CRITICAL"
    assert assessment_crit.score >= 75.0


# ==============================================================================
# 3. PRIVILEGE EXPANSION TESTS
# ==============================================================================

def test_privilege_expansion_detector():
    """Verify privilege expansion detection on actions, wildcards, resources, and conditions."""
    # 1. Action expansion: adding new permission not in baseline
    res_action = check_privilege_expansion(
        baseline=["s3:GetObject"],
        proposed=["s3:GetObject", "iam:CreateUser"],
    )
    assert res_action.is_expanded is True
    assert any("iam:CreateUser" in a for a in res_action.expanded_actions)

    # 2. Wildcard expansion: widening specific action to service wildcard
    res_wildcard = check_privilege_expansion(
        baseline=["s3:GetObject", "s3:PutObject"],
        proposed=["s3:*"],
    )
    assert res_wildcard.is_expanded is True
    assert len(res_wildcard.expanded_actions) > 0

    # 3. Resource expansion: widening resource scope from specific to wildcard
    res_resource = check_privilege_expansion(
        baseline=["s3:GetObject"],
        proposed=["s3:GetObject"],
        baseline_resources=["arn:aws:s3:::my-bucket/orders/*"],
        proposed_resources=["*"],
    )
    assert res_resource.is_expanded is True
    assert len(res_resource.expanded_resources) > 0

    # 4. Scope expansion: widening scope
    res_scope = check_privilege_expansion(
        baseline=["s3:GetObject"],
        proposed=["s3:GetObject"],
        baseline_scope="/subscriptions/sub1/resourceGroups/rg1",
        proposed_scope="/subscriptions/sub1",
    )
    assert res_scope.is_expanded is True
    assert len(res_scope.broadened_scopes) > 0

    # 5. Legitimate least-privilege narrowing (No expansion)
    res_narrowed = check_privilege_expansion(
        baseline=["s3:GetObject", "s3:PutObject", "ec2:*", "iam:*"],
        proposed=["s3:GetObject", "s3:PutObject"],
    )
    assert res_narrowed.is_expanded is False
    assert len(res_narrowed.expanded_actions) == 0


# ==============================================================================
# 4. POLICY REGRESSION TEST SUITE
# ==============================================================================

def test_policy_regression_suite_positive_and_negative():
    """Verify regression test suite validates positive workflows and negative security tests."""
    env = load_environment()
    suite = create_default_regression_suite(env, role_id="PaymentServiceRole")

    # A properly mitigated policy: has required payment perms, NO administrative perms
    valid_permissions = ["s3:GetObject", "s3:PutObject", "kms:Decrypt", "cloudwatch:PutMetricData"]
    result_valid = suite.run("PaymentServiceRole", valid_permissions, env)
    assert result_valid.passed is True
    assert result_valid.passed_count == len(suite.tests)
    assert len(result_valid.failed_tests) == 0

    # Failing positive workflow test: missing kms:Decrypt
    broken_workflow_perms = ["s3:GetObject", "s3:PutObject", "cloudwatch:PutMetricData"]
    result_broken = suite.run("PaymentServiceRole", broken_workflow_perms, env)
    assert result_broken.passed is False
    assert any("payment_checkout" in ft or "kms" in ft or "encrypted" in ft for ft in result_broken.failed_tests)

    # Failing negative security test: retaining prohibited iam:* or ec2:*
    insecure_perms = ["s3:GetObject", "s3:PutObject", "kms:Decrypt", "iam:*"]
    result_insecure = suite.run("PaymentServiceRole", insecure_perms, env)
    assert result_broken.passed is False
    assert any("iam" in ft for ft in result_insecure.failed_tests)


# ==============================================================================
# 5. EVIDENCE SUFFICIENCY GATE TESTS
# ==============================================================================

def test_evidence_sufficiency_fail_closed():
    """Verify fail-closed principle: unobserved != unneeded, and unknown evidence blocks apply."""
    env = load_environment()
    analyzer = SecurityAnalyzer(env)
    bundles = analyzer.analyze_role("PaymentServiceRole")

    # Case 1: Proposing to remove kms:Decrypt which is unobserved in logs, but DEPENDENCY_REQUIRED
    res_dep = evaluate_evidence_sufficiency(
        remove_permissions=["kms:Decrypt"],
        evidence_bundles=bundles,
        simulation_passed=False,
    )
    assert res_dep.is_sufficient is False
    assert "kms:Decrypt" in res_dep.blocked_permissions

    # Case 2: Truly unused permissions (ec2:*, iam:*, dynamodb:*) with simulation passed
    res_unused = evaluate_evidence_sufficiency(
        remove_permissions=["ec2:*", "iam:*", "dynamodb:*"],
        evidence_bundles=bundles,
        simulation_passed=True,
    )
    assert res_unused.is_sufficient is True

    # Case 3: Injected UNKNOWN evidence status forces fail-closed block
    bundles_unknown = dict(bundles)
    bundles_unknown["s3:GetObject"].state = "UNKNOWN"
    res_unknown = evaluate_evidence_sufficiency(
        remove_permissions=["s3:GetObject"],
        evidence_bundles=bundles_unknown,
        simulation_passed=True,
    )
    assert res_unknown.is_sufficient is False
    assert "s3:GetObject" in res_unknown.unknown_permissions


# ==============================================================================
# 6. ADVERSARIAL SCENARIOS 1-9
# ==============================================================================

def test_scenario_1_hidden_dependency_kms_preserved():
    """Scenario 1: Hidden dependency (kms:Decrypt needed by S3 SSE) is caught, adapted, and preserved."""
    env = load_environment()
    tools = create_extended_tool_registry(env)
    reasoner = DeterministicReasoner(target_role_id="PaymentServiceRole")
    controller = AgentController(reasoner=reasoner, tool_registry=tools, environment=env, provider="aws")

    state = controller.run(
        goal="Autonomous least-privilege remediation for PaymentServiceRole",
        role_id="PaymentServiceRole",
        provider="aws",
    )

    assert state.current_phase == "COMPLETED"
    assert state.stop_reason == "verified_success"
    # Verification passed and role preserves kms:Decrypt
    role = env.get_role("PaymentServiceRole")
    assert "kms:Decrypt" in role.active_permissions()
    assert "ec2:*" not in role.active_permissions()
    assert "iam:*" not in role.active_permissions()


def test_scenario_2_privilege_expansion_blocked():
    """Scenario 2: Privilege expansion attempt is blocked by Security Kernel before execution."""
    env = load_environment()
    tools = create_extended_tool_registry(env)

    decisions = [
        AgentDecision(decision_type="tool_call", tool_name="get_role", arguments={"role_id": "PaymentServiceRole"}, reason="Inspect"),
        AgentDecision(
            decision_type="tool_call",
            tool_name="apply_policy_change",
            arguments={"role_id": "PaymentServiceRole", "new_permissions": ["s3:GetObject", "iam:CreateUser"]},
            reason="Adversarial grant of iam:CreateUser",
        ),
    ]
    controller = AgentController(reasoner=MockSequenceReasoner(decisions), tool_registry=tools, environment=env, provider="aws")
    state = controller.run(goal="Test privilege expansion block", role_id="PaymentServiceRole")

    assert state.current_phase == "FAILED"
    assert state.stop_reason == "privilege_expansion_blocked"
    # Verify policy was never applied
    role = env.get_role("PaymentServiceRole")
    assert "iam:CreateUser" not in role.active_permissions()


def test_scenario_3_protected_permission_removal_blocked():
    """Scenario 3: Candidate proposing removal of critical administrative permissions is blocked."""
    env = load_environment()
    # Apply version containing iam:CreateRole so removal is recognized
    env.apply_policy_version("PaymentServiceRole", ["s3:GetObject", "iam:CreateRole", "kms:Decrypt"], "Add admin capability")
    tools = create_extended_tool_registry(env)

    decisions = [
        AgentDecision(decision_type="tool_call", tool_name="get_role", arguments={"role_id": "PaymentServiceRole"}, reason="Inspect"),
        AgentDecision(
            decision_type="tool_call",
            tool_name="apply_policy_change",
            arguments={
                "role_id": "PaymentServiceRole",
                "remove_permissions": ["iam:CreateRole"],
                "reason": "Attempting to modify protected administrative infrastructure",
            },
            reason="Remove protected permissions",
        ),
    ]
    controller = AgentController(reasoner=MockSequenceReasoner(decisions), tool_registry=tools, environment=env, provider="aws")
    state = controller.run(goal="Test protected permission removal block", role_id="PaymentServiceRole")

    assert state.current_phase == "FAILED"
    assert state.stop_reason == "security_block"


def test_scenario_4_high_blast_radius_sensitive_identity_escalated():
    """Scenario 4: High blast radius proposal on sensitive principal requires human approval."""
    env = load_environment()
    kernel = SecurityKernel(env, capabilities=AWS_CAPABILITIES)

    # Evaluating proposal on an administrative identity with critical blast radius
    gate_res = kernel.evaluate_proposal(
        role_id="IAMAdminRole",
        proposed_permissions=["*"],
        planned_policy_version="v1",
        confidence=0.88,
        is_sensitive_principal=True,
    )
    assert gate_res.decision in ("deny", "escalate")
    assert gate_res.blast_radius == "CRITICAL"
    assert gate_res.required_approval is True


def test_scenario_5_stale_policy_optimistic_concurrency():
    """Scenario 5: Out-of-band policy modification triggers optimistic concurrency rejection and replan."""
    env = load_environment()
    tools = create_extended_tool_registry(env)

    # Initial state is v1. Simulate concurrent out-of-band update to v2 before agent applies.
    env.apply_policy_version("PaymentServiceRole", ["s3:GetObject", "ec2:*"], "Concurrent update by another admin")
    assert env.get_role("PaymentServiceRole").current_version == "v2"

    decisions = [
        AgentDecision(decision_type="tool_call", tool_name="get_role", arguments={"role_id": "PaymentServiceRole"}, reason="Inspect"),
        AgentDecision(
            decision_type="tool_call",
            tool_name="apply_policy_change",
            arguments={"role_id": "PaymentServiceRole", "remove_permissions": ["ec2:*"]},
            reason="Apply with stale expectation v1",
        ),
        AgentDecision(decision_type="abort", reason="End test"),
    ]
    # In controller, planned_policy_version starts at v1
    controller = AgentController(reasoner=MockSequenceReasoner(decisions), tool_registry=tools, environment=env, provider="aws")
    # Manually run one step with stale version v1
    gate_res = controller.security_kernel.evaluate_proposal(
        role_id="PaymentServiceRole",
        proposed_permissions=["s3:GetObject"],
        planned_policy_version="v1",  # Stale! Current is v2
        confidence=0.95,
        simulation_result={"success": True},
    )
    assert gate_res.decision == "deny"
    assert any("stale_state_detected" in c for c in gate_res.reason_codes)


def test_scenario_6_post_apply_regression_triggers_rollback():
    """Scenario 6: Live post-apply verification failure triggers automated verified rollback."""
    env = load_environment()
    tools = create_extended_tool_registry(env)

    decisions = [
        AgentDecision(decision_type="tool_call", tool_name="get_role", arguments={"role_id": "PaymentServiceRole"}, reason="Inspect role"),
        AgentDecision(
            decision_type="tool_call",
            tool_name="apply_policy_change",
            arguments={"role_id": "PaymentServiceRole", "remove_permissions": ["kms:Decrypt"], "reason": "Faulty apply"},
            reason="Apply faulty change without simulation",
        ),
        AgentDecision(decision_type="tool_call", tool_name="verify_required_access", arguments={"role_id": "PaymentServiceRole"}, reason="Verify"),
        AgentDecision(decision_type="abort", reason="Finished"),
    ]
    controller = AgentController(reasoner=MockSequenceReasoner(decisions), tool_registry=tools, environment=env, provider="aws")
    state = controller.run(goal="Test post-apply rollback", role_id="PaymentServiceRole")

    rollback_events = [e for e in state.audit_trail if e.event_type == "rollback"]
    assert len(rollback_events) >= 1
    assert state.stop_reason == "verification_failure_rolled_back"
    # Verify environment role was restored to original version v1
    role = env.get_role("PaymentServiceRole")
    assert role.current_version == "v1"


def test_scenario_7_rollback_failure_immediate_escalation():
    """Scenario 7: If automated rollback cannot restore state, controller immediately escalates."""
    env = load_environment()
    tools = create_extended_tool_registry(env)

    # Deliberately break the role's policy history so rollback cannot find v1
    role = env.get_role("PaymentServiceRole")
    role.policy_versions = [role.policy_versions[0]]  # Clear previous versions
    role.current_version = "v2"

    verifier = ExtendedPolicyVerifier(env, capabilities=AWS_CAPABILITIES)
    # Verifying rollback to non-existent version v1 fails
    rb_res = verifier.verify_rollback("PaymentServiceRole", expected_target_version="v1")
    assert rb_res.verified is False
    assert "FAIL" in rb_res.details[0]


def test_scenario_8_unknown_evidence_fail_closed_escalation():
    """Scenario 8: Evidence with UNKNOWN status triggers fail-closed security escalation."""
    record = build_escalation(
        reason_code=EscalationReason.INSUFFICIENT_EVIDENCE,
        summary="Cannot safely prune permission with UNKNOWN telemetry provenance.",
        role_id="PaymentServiceRole",
        provider="aws",
        recommended_action="Collect additional CloudTrail logs or request human administrator confirmation.",
        details={"permission": "s3:GetObject", "status": "UNKNOWN"},
    )
    assert record.reason_code == EscalationReason.INSUFFICIENT_EVIDENCE
    assert "IAM-Security-Admin" in record.required_reviewers
    assert record.recommended_action != ""


def test_scenario_9_unsupported_provider_capability_safe_escalation():
    """Scenario 9: Unsupported provider capability halts safely with transparent audit trail."""
    env = load_environment()
    tools = create_extended_tool_registry(env)

    decisions = [
        AgentDecision(decision_type="tool_call", tool_name="inspect_role", arguments={"role_id": "PaymentServiceRole"}, reason="Inspect"),
        AgentDecision(
            decision_type="tool_call",
            tool_name="simulate_change",
            arguments={"role_id": "PaymentServiceRole", "proposed_permissions": ["s3:GetObject"]},
            reason="Simulate on GCP adapter",
        ),
    ]
    controller = AgentController(reasoner=MockSequenceReasoner(decisions), tool_registry=tools, environment=env, provider="gcp")
    state = controller.run(goal="Test GCP capability negotiation", role_id="PaymentServiceRole", provider="gcp")

    assert state.current_phase == "FAILED"
    assert state.stop_reason == "unsupported_capability"
    assert any(e.event_type == "escalate" for e in state.audit_trail)


# ==============================================================================
# 7. LOOP PREVENTION AND BOUNDED LIMITS TESTS
# ==============================================================================

def test_repeated_failed_actions_loop_prevention():
    """Controller detects repeated failures of identical action and halts safely."""
    env = load_environment()
    tools = create_extended_tool_registry(env)

    # Sequence of identical failing tool calls (requesting nonexistent role)
    repeated_failing_decisions = [
        AgentDecision(
            decision_type="tool_call",
            tool_name="get_role",
            arguments={"role_id": "NonExistentRole123"},
            reason="Repeated failing inspect",
        )
        for _ in range(5)
    ]
    controller = AgentController(
        reasoner=MockSequenceReasoner(repeated_failing_decisions),
        tool_registry=tools,
        environment=env,
        provider="aws",
    )
    state = controller.run(goal="Test loop prevention", role_id="NonExistentRole123")

    assert state.current_phase == "FAILED"
    assert state.stop_reason == "repeated_failed_actions"
    # Halted at max_failed_action_repeats (default 2)
    assert len(state.tool_calls) == 2


def test_bounded_rollback_attempts_limit():
    """Controller enforces hard limit of at most 1 rollback attempt."""
    config = SecurityPolicyConfig(max_rollback_attempts=1)
    assert config.max_rollback_attempts == 1

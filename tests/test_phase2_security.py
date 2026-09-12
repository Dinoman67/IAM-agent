"""Tests for Security Kernel, Gate, Evidence, Diff, Capabilities, and IR."""

import pytest

from backend.environment.loader import load_environment
from backend.models.evidence import Evidence, EvidenceBundle, EvidenceSource, EvidenceState, EvidenceStrength
from backend.models.iam import CommonAction, CommonPolicy, CommonResource, PolicyEffect
from backend.providers.capabilities import AWS_CAPABILITIES, GCP_CAPABILITIES, RESTRICTED_MOCK_CAPABILITIES
from backend.security.analyzer import SecurityAnalyzer
from backend.security.dependency import DependencyGraph
from backend.security.diff import compute_policy_diff
from backend.security.kernel import SecurityKernel
from backend.security.verification import ExtendedPolicyVerifier


def test_security_gate_denies_stale_state():
    """Security Kernel denies proposal if policy version changed since planning."""
    env = load_environment()
    kernel = SecurityKernel(env)

    # Planned on 'v1', but current is 'v1' -> simulate external mutation to 'v2'
    env.apply_policy_version("PaymentServiceRole", ["s3:GetObject"], "External update")

    gate_result = kernel.evaluate_proposal(
        role_id="PaymentServiceRole",
        proposed_permissions=["s3:GetObject", "kms:Decrypt"],
        planned_policy_version="v1",  # stale! current is now v2
        confidence=0.95,
        simulation_result={"success": True},
    )

    assert gate_result.decision == "deny"
    assert "stale_state_detected" in gate_result.reason_codes
    assert gate_result.required_approval is True


def test_security_gate_denies_failed_simulation():
    """Security Kernel blocks policy mutation if counterfactual simulation failed."""
    env = load_environment()
    kernel = SecurityKernel(env)

    gate_result = kernel.evaluate_proposal(
        role_id="PaymentServiceRole",
        proposed_permissions=["s3:GetObject"],
        planned_policy_version="v1",
        confidence=0.95,
        simulation_result={"success": False, "failed_workflow": "payment_checkout"},
    )

    assert gate_result.decision == "deny"
    assert "simulation_failed" in gate_result.reason_codes


def test_security_gate_denies_exposed_sensitive_resource():
    """Security Kernel denies proposed policy that exposes sensitive protected resources."""
    env = load_environment()
    kernel = SecurityKernel(env)

    # Proposal includes dynamodb:* which exposes res-dynamodb-pii
    gate_result = kernel.evaluate_proposal(
        role_id="PaymentServiceRole",
        proposed_permissions=["s3:GetObject", "dynamodb:*"],
        planned_policy_version="v1",
        confidence=0.95,
        simulation_result={"success": True},
    )

    assert gate_result.decision == "deny"
    assert any("sensitive_resource_exposed" in c for c in gate_result.reason_codes)


def test_security_gate_escalates_on_unsupported_provider_capabilities():
    """If provider lacks rollback or versioning capabilities, Kernel escalates to human approval."""
    env = load_environment()
    # Restricted mock without rollback
    kernel = SecurityKernel(env, capabilities=RESTRICTED_MOCK_CAPABILITIES)

    gate_result = kernel.evaluate_proposal(
        role_id="PaymentServiceRole",
        proposed_permissions=["s3:GetObject", "s3:PutObject", "kms:Decrypt", "cloudwatch:PutMetricData"],
        planned_policy_version="v1",
        confidence=0.95,
        simulation_result={"success": True},
    )

    assert gate_result.decision == "escalate"
    assert "unsupported_capability_no_rollback" in gate_result.reason_codes
    assert gate_result.required_approval is True


def test_security_gate_escalates_on_low_confidence():
    """If agent confidence is below threshold, Kernel requires escalation."""
    env = load_environment()
    kernel = SecurityKernel(env, min_confidence_for_apply=0.85)

    gate_result = kernel.evaluate_proposal(
        role_id="PaymentServiceRole",
        proposed_permissions=["s3:GetObject", "s3:PutObject", "kms:Decrypt", "cloudwatch:PutMetricData"],
        planned_policy_version="v1",
        confidence=0.60,  # low confidence
        simulation_result={"success": True},
    )

    assert gate_result.decision == "escalate"
    assert "insufficient_confidence" in gate_result.reason_codes


def test_security_gate_allows_safe_simulated_change():
    """Security Kernel allows compliant proposal with passing simulation and fresh state."""
    env = load_environment()
    kernel = SecurityKernel(env, capabilities=AWS_CAPABILITIES)

    gate_result = kernel.evaluate_proposal(
        role_id="PaymentServiceRole",
        proposed_permissions=["s3:GetObject", "s3:PutObject", "kms:Decrypt", "cloudwatch:PutMetricData"],
        planned_policy_version="v1",
        confidence=0.95,
        simulation_result={"success": True},
        risk_level="low",
    )

    assert gate_result.decision == "allow"
    assert len(gate_result.reason_codes) == 0
    assert gate_result.required_approval is False


def test_evidence_model_states_and_bundles():
    """Verify distinction: NOT_OBSERVED != PROVEN_UNNEEDED, and bundle recomputation."""
    bundle = EvidenceBundle(permission="kms:Decrypt")
    assert bundle.state == EvidenceState.UNKNOWN

    # 1. Unlogged in access logs -> NOT_OBSERVED
    ev_log = Evidence(
        source=EvidenceSource.ACCESS_LOGS,
        permission="kms:Decrypt",
        claim="Not observed in logs",
        strength=EvidenceStrength.MEDIUM,
        state=EvidenceState.NOT_OBSERVED,
    )
    bundle.add_evidence(ev_log)
    assert bundle.state == EvidenceState.NOT_OBSERVED
    assert bundle.removal_permitted is False  # Cannot remove based merely on absence of logs!

    # 2. Dependency discovered -> DEPENDENCY_REQUIRED
    ev_dep = Evidence(
        source=EvidenceSource.DEPENDENCY_GRAPH,
        permission="kms:Decrypt",
        claim="Required for S3 SSE Decryption",
        strength=EvidenceStrength.PROVEN,
        state=EvidenceState.DEPENDENCY_REQUIRED,
    )
    bundle.add_evidence(ev_dep)
    assert bundle.state == EvidenceState.DEPENDENCY_REQUIRED
    assert bundle.risk == "critical"
    assert bundle.removal_permitted is False


def test_security_analyzer_bundles_role():
    """SecurityAnalyzer accurately bundles all role permissions with evidence."""
    env = load_environment()
    analyzer = SecurityAnalyzer(env)

    bundles = analyzer.analyze_role("PaymentServiceRole")
    assert "s3:GetObject" in bundles
    assert bundles["s3:GetObject"].state == EvidenceState.USED

    assert "kms:Decrypt" in bundles
    # kms:Decrypt is in dependencies
    assert bundles["kms:Decrypt"].state == EvidenceState.DEPENDENCY_REQUIRED

    assert "ec2:*" in bundles
    assert bundles["ec2:*"].state == EvidenceState.NOT_OBSERVED


def test_dependency_investigation_graph():
    """DependencyGraph discovers transitive coupling between PaymentService, S3, and KMS."""
    env = load_environment()
    graph = DependencyGraph(env)

    chain = graph.explain_missing_permission("PaymentService", "kms:Decrypt")
    assert chain is not None
    assert chain.service == "PaymentService"
    assert chain.intermediary == "S3"
    assert chain.target_service == "KMS"
    assert chain.required_permission == "kms:Decrypt"
    assert "SSE" in chain.reason


def test_policy_diff_generation_and_markdown():
    """compute_policy_diff produces accurate diff categorizations and renders markdown."""
    diff = compute_policy_diff(
        role_id="PaymentServiceRole",
        from_version="v1",
        to_version="v2",
        original_permissions=["s3:GetObject", "s3:PutObject", "kms:Decrypt", "ec2:*", "iam:*"],
        new_permissions=["s3:GetObject", "s3:PutObject", "kms:Decrypt"],
        retained_dependencies=["kms:Decrypt"],
    )

    assert set(diff.removed) == {"ec2:*", "iam:*"}
    assert set(diff.kept) == {"s3:GetObject", "s3:PutObject", "kms:Decrypt"}
    assert "KMS SSE decryption" in diff.why_kept["kms:Decrypt"]

    md = diff.render_markdown()
    assert "REMOVED Permissions (-)" in md
    assert "- `- ec2:*`" in md
    assert "KEPT Permissions (+)" in md
    assert "`+ kms:Decrypt`" in md


def test_common_iam_ir_and_conversions():
    """Common IAM Intermediate Representation models serialize and parse correctly."""
    policy = CommonPolicy.from_permissions_list(
        policy_id="pol-1",
        name="TestPolicy",
        permissions=["s3:GetObject", "kms:Decrypt"],
        version="v1",
    )
    assert len(policy.statements) == 1
    stmt = policy.statements[0]
    assert stmt.effect == PolicyEffect.ALLOW
    assert len(stmt.actions) == 2
    assert stmt.actions[0].service == "s3"
    assert stmt.actions[0].operation == "GetObject"

    extracted = policy.extract_permission_strings()
    assert extracted == ["s3:GetObject", "kms:Decrypt"]


def test_extended_verifier_comprehensive_checks():
    """ExtendedPolicyVerifier evaluates functional, security, structural, and provider checks."""
    env = load_environment()
    verifier = ExtendedPolicyVerifier(env)

    # Initial v1 policy has excessive wildcards -> should fail security
    res_initial = verifier.verify_remediation("PaymentServiceRole")
    assert res_initial.functional_passed is True
    assert res_initial.security_passed is False  # exposes sensitive resources
    assert res_initial.passed is False

    # Apply proper mitigation
    env.apply_policy_version(
        "PaymentServiceRole",
        ["s3:GetObject", "s3:PutObject", "kms:Decrypt", "cloudwatch:PutMetricData"],
        "Mitigated",
    )

    res_mitigated = verifier.verify_remediation(
        "PaymentServiceRole",
        expected_permissions=["s3:GetObject", "s3:PutObject", "kms:Decrypt", "cloudwatch:PutMetricData"],
    )
    assert res_mitigated.passed is True
    assert res_mitigated.functional_passed is True
    assert res_mitigated.security_passed is True
    assert res_mitigated.structural_passed is True
    assert res_mitigated.should_rollback is False

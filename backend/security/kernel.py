"""Deterministic Security Kernel and Authorization Gate.

The Security Kernel is the authoritative control boundary. The AI proposes,
but the deterministic Kernel validates, authorizes, or rejects changes.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, Sequence
from pydantic import BaseModel, Field

from backend.environment.loader import IAMEnvironment
from backend.environment.simulator import PolicySimulator
from backend.models.evidence import EvidenceBundle, EvidenceState
from backend.providers.capabilities import AWS_CAPABILITIES, ProviderCapabilities
from backend.security.blast_radius import BlastRadiusAssessment, calculate_blast_radius
from backend.security.escalation import EscalationReason
from backend.security.evidence_gate import evaluate_evidence_sufficiency
from backend.security.expansion import check_privilege_expansion
from backend.security.invariants import (
    GateDecision,
    SecurityDecision,
    SecurityGateResult,
    SecurityInvariant,
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
)
from backend.security.policy_config import (
    DEFAULT_SECURITY_POLICY_CONFIG,
    SecurityPolicyConfig,
)
from backend.security.regression import RegressionTestSuite, create_default_regression_suite


class SecurityKernel:
    """Independent deterministic authority governing IAM mutations across all cloud providers."""

    def __init__(
        self,
        env: IAMEnvironment,
        capabilities: Optional[ProviderCapabilities] = None,
        min_confidence_for_apply: Optional[float] = None,
        config: Optional[SecurityPolicyConfig] = None,
    ) -> None:
        self.env = env
        self.capabilities = capabilities or AWS_CAPABILITIES
        self.config = config or DEFAULT_SECURITY_POLICY_CONFIG
        if min_confidence_for_apply is not None:
            self.min_confidence = min_confidence_for_apply
        else:
            self.min_confidence = self.config.min_confidence_for_apply

        # Backward-compatible reference to protected permissions
        self.PROTECTED_PERMISSIONS = self.config.protected_permissions

    def evaluate_proposal(
        self,
        role_id: str,
        proposed_permissions: List[str],
        planned_policy_version: str,
        confidence: float,
        simulation_result: Optional[Dict[str, Any]] = None,
        risk_level: str = "medium",
        provider: Optional[str] = None,
        evidence_bundles: Optional[Dict[str, EvidenceBundle]] = None,
        regression_suite: Optional[RegressionTestSuite] = None,
        is_sensitive_principal: bool = False,
        resources_affected: Optional[Sequence[str]] = None,
        baseline_resources: Optional[Sequence[str]] = None,
        proposed_resources: Optional[Sequence[str]] = None,
        baseline_scope: Optional[str] = None,
        proposed_scope: Optional[str] = None,
    ) -> SecurityGateResult:
        """Deterministically evaluates if proposed policy change is authorized for application.
        
        Evaluates:
        - Role existence
        - Provider mismatch protection
        - Stale state protection (optimistic concurrency)
        - Privilege expansion protection (actions, wildcards, resources, conditions, scopes)
        - Deterministic blast radius evaluation
        - Protected permissions and resources protection
        - Transitive dependency protection
        - Evidence sufficiency and unknown evidence protection
        - Counterfactual simulation verification
        - Pre-apply policy regression suite (positive workflows & negative security tests)
        - Autonomy level gates (SAFE, ASSISTED, STRICT)
        """
        role = self.env.get_role(role_id)
        if not role:
            return SecurityGateResult(
                allowed=False,
                decision="deny",
                reason="Role not found in environment.",
                reason_codes=["role_not_found"],
                required_approval=True,
                risk_level="critical",
                confidence=1.0,
                blast_radius="CRITICAL",
                violated_invariants=[],
                details={"error": f"Role '{role_id}' does not exist."},
            )

        reason_codes: List[str] = []
        details: Dict[str, Any] = {}
        violated_invariants: List[SecurityInvariant] = []
        required_verification: List[str] = []
        escalation_reason: Optional[str] = None

        original_perms = set(role.active_permissions())
        proposed_perms_set = set(proposed_permissions)
        removed_perms = original_perms - proposed_perms_set

        # 1. Provider Mismatch Protection
        target_provider = self.capabilities.provider_name.lower()
        if provider and provider.lower() != target_provider:
            code = f"provider_mismatch:{provider}_vs_{target_provider}"
            reason_codes.append(code)
            violated_invariants.append(INVARIANT_NO_CROSS_PROVIDER_MUTATION)
            escalation_reason = EscalationReason.CROSS_TENANT_VIOLATION.value
            details["provider_mismatch"] = {
                "source_provider": provider,
                "target_provider": target_provider,
                "reason": "Cannot apply changes destined for another cloud provider environment",
            }

        # 2. Stale State Protection (Optimistic Concurrency)
        if role.current_version != planned_policy_version:
            reason_codes.append("stale_state_detected")
            violated_invariants.append(INVARIANT_NO_STALE_STATE_MUTATION)
            escalation_reason = EscalationReason.STALE_STATE.value
            details["stale_state"] = {
                "expected_version": planned_policy_version,
                "current_version": role.current_version,
            }

        # 3. Comprehensive Privilege Expansion Check
        # Restoration of permissions the role held in a PRIOR version is not
        # expansion (all other gates — simulation, regression, protected
        # resources, evidence — still apply). This enables honest recovery by
        # re-binding a previously held least-privilege set.
        historical_perms: set = set()
        for v in role.policy_versions:
            historical_perms.update(v.permissions or [])

        expansion_result = check_privilege_expansion(
            baseline=list(original_perms),
            proposed=proposed_permissions,
            baseline_resources=baseline_resources,
            proposed_resources=proposed_resources,
            baseline_scope=baseline_scope,
            proposed_scope=proposed_scope,
        )

        expansion = proposed_perms_set - original_perms
        restored = {p for p in expansion if p in historical_perms}
        true_expansion = expansion - restored
        if restored:
            details["restored_permissions"] = sorted(restored)
        # Non-action dimensions (resources/scopes/conditions) are unaffected by
        # restoration and keep their original strictness.
        non_action_expansion = [
            t for t in expansion_result.expansion_types if t != "action_expansion"
        ]
        if true_expansion or non_action_expansion:
            violated_invariants.append(INVARIANT_NO_PRIVILEGE_EXPANSION)
            escalation_reason = EscalationReason.PRIVILEGE_EXPANSION.value
            for p in sorted(list(true_expansion)):
                reason_codes.append(f"unauthorized_privilege_expansion:{p}")
            details["privilege_expansion"] = sorted(true_expansion)
            details["expansion_analysis"] = expansion_result.model_dump()

        # 4. Protected Permissions Check (Configurable)
        # Check if protected permissions are retained or granted
        for p in proposed_permissions:
            if p in self.PROTECTED_PERMISSIONS or self.config.is_permission_protected(p):
                reason_codes.append(f"protected_permission_retained:{p}")
                if INVARIANT_NO_PROTECTED_PERMISSION_MUTATION not in violated_invariants:
                    violated_invariants.append(INVARIANT_NO_PROTECTED_PERMISSION_MUTATION)

        # Check if specific sensitive administrative capabilities are removed without approval
        for p in removed_perms:
            if self.config.is_sensitive_action_removed(p):
                reason_codes.append(f"protected_permission_removed:{p}")
                if INVARIANT_NO_PROTECTED_PERMISSION_MUTATION not in violated_invariants:
                    violated_invariants.append(INVARIANT_NO_PROTECTED_PERMISSION_MUTATION)

        # 5. Sensitive Resources Isolation Check (Configurable)
        exposed_resources: List[str] = []
        for resource in self.env.data.resources:
            # Check either environment flag or config patterns
            if resource.is_protected or self.config.is_resource_protected(resource.arn or resource.id):
                for perm in resource.required_permissions:
                    if PolicySimulator.is_action_allowed(perm, proposed_permissions):
                        code = f"sensitive_resource_exposed:{resource.id}"
                        reason_codes.append(code)
                        exposed_resources.append(resource.id)
                        if INVARIANT_NO_PROTECTED_RESOURCE_EXPOSURE not in violated_invariants:
                            violated_invariants.append(INVARIANT_NO_PROTECTED_RESOURCE_EXPOSURE)

        if exposed_resources:
            details["exposed_sensitive_resources"] = exposed_resources

        # 6. Provider Capabilities Check
        # Providers with sandbox local evaluation emulate versioning/impact
        # analysis deterministically; the sandbox records this substitution
        # instead of treating emulated capabilities as violations.
        local_eval = bool(getattr(self.capabilities, "supports_local_evaluation", False))
        if not self.capabilities.supports_policy_simulation and simulation_result is None:
            reason_codes.append("unsupported_capability_no_simulation")
            escalation_reason = EscalationReason.UNSUPPORTED_PROVIDER_OPERATION.value
        if not self.capabilities.supports_policy_versioning:
            if local_eval:
                details["local_evaluation_versioning"] = (
                    "Sandbox emulates policy revisions for local evaluation; "
                    "native provider versioning not claimed."
                )
            else:
                reason_codes.append("unsupported_capability_no_versioning")
                escalation_reason = EscalationReason.UNSUPPORTED_PROVIDER_OPERATION.value
        if not self.capabilities.supports_rollback:
            if local_eval:
                details["local_evaluation_rollback"] = (
                    "Sandbox has no atomic rollback; recovery proceeds by re-binding "
                    "prior permissions through the standard apply path."
                )
            else:
                reason_codes.append("unsupported_capability_no_rollback")
                escalation_reason = EscalationReason.UNSUPPORTED_PROVIDER_OPERATION.value

        # 7. Simulation Verification Check
        if simulation_result is not None:
            if not simulation_result.get("success", False):
                reason_codes.append("simulation_failed")
                violated_invariants.append(INVARIANT_NO_MUTATION_WITHOUT_SIMULATION)
                escalation_reason = EscalationReason.VERIFICATION_FAILURE.value
                details["failed_workflow"] = simulation_result.get("failed_workflow")
                details["missing_permission"] = simulation_result.get("missing_permission")
                details["broken_dependency"] = simulation_result.get("broken_dependency")
        else:
            if self.capabilities.supports_policy_simulation and self.config.require_simulation:
                reason_codes.append("unsimulated_change_denied")
                violated_invariants.append(INVARIANT_NO_MUTATION_WITHOUT_SIMULATION)

        # 8. Deterministic Blast Radius Assessment
        touches_prot_res = len(exposed_resources) > 0 or any(
            self.config.is_resource_protected(r) for r in (resources_affected or [])
        )
        dependencies = self.env.get_service_dependencies()
        blast_assessment: BlastRadiusAssessment = calculate_blast_radius(
            original_permissions=list(original_perms),
            proposed_permissions=proposed_permissions,
            resources_affected=resources_affected,
            principal_id=role_id,
            principal_type="admin" if "admin" in role_id.lower() else "service",
            is_sensitive_principal=is_sensitive_principal or ("admin" in role_id.lower()),
            dependencies_count=len(dependencies),
            touches_protected_resource=touches_prot_res,
            provider=self.capabilities.provider_name,
            protected_permissions=list(self.config.protected_permissions),
        )
        details["blast_radius"] = blast_assessment.model_dump()
        evaluated_blast = blast_assessment.level

        # 9. Evidence Sufficiency Check (Fail-closed on UNKNOWN or unproven unobserved permissions)
        if evidence_bundles:
            sim_passed = bool(simulation_result and simulation_result.get("success", False))
            ev_result = evaluate_evidence_sufficiency(
                remove_permissions=list(removed_perms),
                evidence_bundles=evidence_bundles,
                simulation_passed=sim_passed,
                risk_level=risk_level,
            )
            details["evidence_sufficiency"] = ev_result.model_dump()
            if not ev_result.is_sufficient:
                violated_invariants.append(INVARIANT_NO_MUTATION_WITHOUT_EVIDENCE)
                escalation_reason = EscalationReason.INSUFFICIENT_EVIDENCE.value
                for r in ev_result.reasons:
                    reason_codes.append(f"insufficient_evidence:{r}")

        # 10. Pre-Apply Policy Regression Test Suite
        if self.config.require_regression_tests:
            suite = regression_suite or create_default_regression_suite(self.env, role_id=role_id)
            reg_result = suite.run(role_id=role_id, permissions=proposed_permissions, env=self.env)
            details["pre_apply_regression"] = reg_result.model_dump()
            if not reg_result.passed:
                violated_invariants.append(INVARIANT_NO_MUTATION_WITHOUT_PRE_APPLY_VERIFICATION)
                escalation_reason = EscalationReason.VERIFICATION_FAILURE.value
                for ft in reg_result.failed_tests:
                    reason_codes.append(f"regression_test_failed:{ft}")

        # 11. Confidence and Risk Gating
        if confidence < self.min_confidence:
            reason_codes.append("insufficient_confidence")
            if not escalation_reason:
                escalation_reason = EscalationReason.INSUFFICIENT_EVIDENCE.value

        # Blast radius checks against autonomy level
        if evaluated_blast == "CRITICAL":
            reason_codes.append("blast_radius_critical")
            violated_invariants.append(INVARIANT_NO_UNAPPROVED_HIGH_RISK)
            if not escalation_reason:
                escalation_reason = EscalationReason.HIGH_RISK.value
        elif evaluated_blast == "HIGH":
            reason_codes.append("blast_radius_high")
            if not escalation_reason:
                escalation_reason = EscalationReason.HIGH_RISK.value

        # -------------------------------------------------------------
        # Gate Decision Logic
        # -------------------------------------------------------------
        # Hard Deny Conditions: cannot be bypassed
        hard_deny_codes = [
            c for c in reason_codes
            if "stale_state" in c
            or "simulation_failed" in c
            or "sensitive_resource_exposed" in c
            or "unsimulated_change" in c
            or "provider_mismatch" in c
            or "unauthorized_privilege_expansion" in c
            or "regression_test_failed" in c
            or "blast_radius_critical" in c
        ]

        if hard_deny_codes:
            return SecurityGateResult(
                allowed=False,
                decision="deny",
                reason=f"Security Kernel DENIED proposal due to hard security invariant violations: {hard_deny_codes}",
                reason_codes=reason_codes,
                required_approval=True,
                risk_level="critical" if "blast_radius_critical" in reason_codes else "high",
                confidence=confidence,
                blast_radius=evaluated_blast,
                violated_invariants=violated_invariants,
                required_verification=["re_simulation", "invariant_audit"],
                escalation_reason=escalation_reason or EscalationReason.SECURITY_INVARIANT_VIOLATION.value,
                details=details,
            )

        # Escalation Conditions: requires human sign-off
        escalate_codes = [
            c for c in reason_codes
            if "unsupported_capability" in c
            or "insufficient_confidence" in c
            or "protected_permission" in c
            or "insufficient_evidence" in c
            or "blast_radius_high" in c
        ]

        # Autonomy level restrictions
        requires_escalate_by_autonomy = False
        autonomy = self.config.autonomy_level
        if autonomy == "STRICT":
            # Autonomous only for LOW risk and VERY HIGH confidence (>= 0.95)
            if evaluated_blast != "LOW" or risk_level != "low" or confidence < 0.95:
                requires_escalate_by_autonomy = True
        elif autonomy == "ASSISTED":
            # Autonomous only for LOW risk
            if evaluated_blast != "LOW" or risk_level != "low":
                requires_escalate_by_autonomy = True
        else:  # SAFE
            if evaluated_blast in ["HIGH", "CRITICAL"] or risk_level in ["high", "critical"]:
                requires_escalate_by_autonomy = True

        if escalate_codes or requires_escalate_by_autonomy or confidence < 0.90:
            if not escalation_reason:
                if any("protected_permission" in c for c in reason_codes):
                    escalation_reason = EscalationReason.CRITICAL_PERMISSION.value
                elif any("unsupported_capability" in c for c in reason_codes):
                    escalation_reason = EscalationReason.UNSUPPORTED_PROVIDER_OPERATION.value
                elif any("insufficient_confidence" in c for c in reason_codes):
                    escalation_reason = EscalationReason.INSUFFICIENT_EVIDENCE.value
                elif evaluated_blast in ["HIGH", "CRITICAL"]:
                    escalation_reason = EscalationReason.HIGH_RISK.value
                else:
                    escalation_reason = EscalationReason.HIGH_RISK.value

            return SecurityGateResult(
                allowed=False,
                decision="escalate",
                reason=f"Security Kernel requires human review ({escalation_reason}): {reason_codes}",
                reason_codes=reason_codes,
                required_approval=True,
                risk_level=risk_level if risk_level in ["high", "critical"] else ("high" if evaluated_blast == "HIGH" else "medium"),
                confidence=confidence,
                blast_radius=evaluated_blast,
                violated_invariants=violated_invariants,
                required_verification=["human_review", "stating_test"],
                escalation_reason=escalation_reason,
                details=details,
            )

        # Allow: Low/Medium Risk + High Confidence + Simulated + Verified + Fresh State
        return SecurityGateResult(
            allowed=True,
            decision="allow",
            reason="Security Kernel AUTHORIZED policy mutation: all deterministic invariants satisfied.",
            reason_codes=[],
            required_approval=False,
            risk_level=risk_level,
            confidence=confidence,
            blast_radius=evaluated_blast,
            violated_invariants=[],
            required_verification=["post_apply_verification"],
            details={"approved": True, **details},
        )


__all__ = [
    "GateDecision",
    "SecurityGateResult",
    "SecurityDecision",
    "SecurityKernel",
]

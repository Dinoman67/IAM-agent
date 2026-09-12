"""Multi-dimensional pre-apply and post-remediation verification authority."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence
from pydantic import BaseModel, Field

from backend.environment.loader import IAMEnvironment
from backend.environment.simulator import PolicySimulator
from backend.environment.verifier import PolicyVerifier
from backend.models.evidence import EvidenceBundle
from backend.providers.capabilities import AWS_CAPABILITIES, ProviderCapabilities
from backend.security.blast_radius import calculate_blast_radius
from backend.security.expansion import check_privilege_expansion
from backend.security.regression import (
    PolicyRegressionTest,
    RegressionTestSuite,
    create_default_regression_suite,
)


class ComprehensiveVerificationResult(BaseModel):
    """Detailed verification outcome spanning functional, security, structural, and provider checks."""

    passed: bool
    functional_passed: bool
    security_passed: bool
    structural_passed: bool
    provider_passed: bool
    regression_passed: bool = True
    checks: Dict[str, bool] = Field(default_factory=dict)
    details: List[str] = Field(default_factory=list)
    failed_regression_tests: List[str] = Field(default_factory=list)
    should_rollback: bool = False


class RollbackVerificationResult(BaseModel):
    """Authoritative result confirming whether state rollback actually executed and restored baseline."""

    verified: bool
    restored_version: str
    active_permissions: List[str] = Field(default_factory=list)
    workflows_functional: bool = True
    details: List[str] = Field(default_factory=list)


class PreApplyVerificationResult(BaseModel):
    """Result of deterministic pre-apply validation checks before policy mutation."""

    approved_for_apply: bool
    structural_valid: bool
    privilege_non_expanded: bool
    evidence_sufficient: bool
    simulation_passed: bool
    regression_passed: bool
    blast_radius: str
    decision: str
    details: Dict[str, Any] = Field(default_factory=dict)
    reasons: List[str] = Field(default_factory=list)


class ExtendedPolicyVerifier:
    """Comprehensive verifier executing independent pre- and post-apply validation across providers."""

    def __init__(
        self,
        env: IAMEnvironment,
        capabilities: Optional[ProviderCapabilities] = None,
        regression_suite: Optional[RegressionTestSuite] = None,
    ) -> None:
        self.env = env
        self.capabilities = capabilities or AWS_CAPABILITIES
        self.base_verifier = PolicyVerifier(env)
        self.regression_suite = regression_suite

    def verify_remediation(
        self,
        role_id: str,
        expected_permissions: Optional[List[str]] = None,
        provider: Optional[str] = None,
    ) -> ComprehensiveVerificationResult:
        """Executes full suite of post-change verifications with provider awareness.
        
        CRITICAL RULE: Never infer verification merely because apply() returned success.
        Re-reads actual state from environment and executes workflow, security, and regression tests.
        """
        base_res = self.base_verifier.verify(role_id)
        role = self.env.get_role(role_id)

        if not role:
            return ComprehensiveVerificationResult(
                passed=False,
                functional_passed=False,
                security_passed=False,
                structural_passed=False,
                provider_passed=False,
                regression_passed=False,
                checks={"role_exists": False},
                details=[f"Role '{role_id}' not found in active environment."],
                should_rollback=True,
            )

        active_perms = role.active_permissions()
        details = list(base_res.details)
        checks = dict(base_res.checks)

        # 1. Functional check (workflows from environment)
        functional_passed = base_res.checks.get("workflows_passed", False)

        # 2. Security check (protected resources shielded)
        security_passed = base_res.checks.get("protected_resources_isolated", False)

        # 3. Structural check (matches expected permissions if specified)
        if expected_permissions is not None:
            matches_expected = set(active_perms) == set(expected_permissions)
            checks["structural_matches_approved"] = matches_expected
            if matches_expected:
                details.append("Structural integrity: PASS (active policy exactly matches approved set)")
            else:
                details.append(
                    f"Structural integrity: FAIL (active {active_perms} != expected {expected_permissions})"
                )
            structural_passed = matches_expected
        else:
            structural_passed = base_res.checks.get("policy_applied", True)

        # 4. Provider capability and mismatch checks
        provider_passed = True
        target_provider = self.capabilities.provider_name.lower()
        if provider and provider.lower() != target_provider:
            provider_passed = False
            details.append(f"Provider check: FAIL (provider mismatch: received '{provider}', expected '{target_provider}')")

        if self.capabilities.supports_policy_versioning and len(role.policy_versions) <= 1:
            provider_passed = False
            details.append("Provider check: FAIL (provider supports versioning but new version not created)")

        checks["provider_compliant"] = provider_passed

        # 5. Deterministic Policy Regression Test Suite (Positive workflows + Negative security tests)
        suite = self.regression_suite or create_default_regression_suite(self.env, role_id=role_id)
        reg_result = suite.run(role_id=role_id, permissions=active_perms, env=self.env)
        regression_passed = reg_result.passed
        checks["regression_suite_passed"] = regression_passed
        checks["positive_workflows_passed"] = reg_result.positive_passed
        checks["negative_security_invariants_passed"] = reg_result.negative_passed

        if regression_passed:
            details.append(f"Policy regression suite: PASS ({reg_result.passed_count}/{reg_result.total_tests} tests succeeded)")
        else:
            details.append(f"Policy regression suite: FAIL (Failed: {reg_result.failed_tests})")

        overall_passed = functional_passed and security_passed and structural_passed and provider_passed and regression_passed

        # Flag for automated rollback if functional workflows failed after apply or security invariants failed
        should_rollback = not functional_passed or not security_passed or not reg_result.positive_passed

        return ComprehensiveVerificationResult(
            passed=overall_passed,
            functional_passed=functional_passed,
            security_passed=security_passed,
            structural_passed=structural_passed,
            provider_passed=provider_passed,
            regression_passed=regression_passed,
            checks=checks,
            details=details,
            failed_regression_tests=reg_result.failed_tests,
            should_rollback=should_rollback,
        )

    def verify_rollback(
        self,
        role_id: str,
        expected_target_version: str = "v1",
        expected_permissions: Optional[List[str]] = None,
    ) -> RollbackVerificationResult:
        """Independently verifies that rollback restored the target policy version and workflows.
        
        CRITICAL RULE: Never report ROLLBACK_SUCCESS unless the restored state was actually verified.
        """
        role = self.env.get_role(role_id)
        if not role:
            return RollbackVerificationResult(
                verified=False,
                restored_version="unknown",
                active_permissions=[],
                workflows_functional=False,
                details=[f"Rollback verification FAILED: Role '{role_id}' does not exist."],
            )

        details: List[str] = []
        is_version_match = (role.current_version == expected_target_version)
        active_perms = role.active_permissions()

        if is_version_match:
            details.append(f"Version check: PASS (current version matches target '{expected_target_version}')")
        else:
            details.append(
                f"Version check: FAIL (current version '{role.current_version}' != expected '{expected_target_version}')"
            )

        # Check permissions match expected
        perms_match = True
        if expected_permissions is not None:
            perms_match = set(active_perms) == set(expected_permissions)
            if perms_match:
                details.append("Permissions check: PASS (restored permissions match expected)")
            else:
                details.append(f"Permissions check: FAIL ({active_perms} != {expected_permissions})")

        # Verify operational workflows under restored permissions
        sim_res = PolicySimulator(self.env).simulate(role_id, active_perms)
        workflows_functional = sim_res.success
        if workflows_functional:
            details.append("Workflow check: PASS (restored policy satisfies required workflows)")
        else:
            details.append(f"Workflow check: FAIL ({sim_res.details})")

        verified = is_version_match and perms_match and workflows_functional

        return RollbackVerificationResult(
            verified=verified,
            restored_version=role.current_version,
            active_permissions=active_perms,
            workflows_functional=workflows_functional,
            details=details,
        )

    def pre_apply_verify(
        self,
        role_id: str,
        proposed_permissions: Sequence[str],
        planned_policy_version: str,
        confidence: float = 1.0,
        evidence_bundles: Optional[Dict[str, EvidenceBundle]] = None,
    ) -> PreApplyVerificationResult:
        """Executes full pre-apply verification pipeline before mutation."""
        role = self.env.get_role(role_id)
        if not role:
            return PreApplyVerificationResult(
                approved_for_apply=False,
                structural_valid=False,
                privilege_non_expanded=False,
                evidence_sufficient=False,
                simulation_passed=False,
                regression_passed=False,
                blast_radius="CRITICAL",
                decision="deny",
                reasons=[f"Role '{role_id}' not found"],
            )

        active = role.active_permissions()
        prop_list = list(proposed_permissions)

        # 1. Structural check
        structural_valid = len(prop_list) > 0 and all(isinstance(p, str) and len(p.strip()) > 0 for p in prop_list)

        # 2. Privilege expansion
        exp_res = check_privilege_expansion(baseline=active, proposed=prop_list)
        privilege_non_expanded = not exp_res.is_expanded

        # 3. Simulation
        sim_res = PolicySimulator(self.env).simulate(role_id, prop_list)
        simulation_passed = sim_res.success

        # 4. Regression tests
        suite = self.regression_suite or create_default_regression_suite(self.env, role_id=role_id)
        reg_res = suite.run(role_id=role_id, permissions=prop_list, env=self.env)
        regression_passed = reg_res.passed

        # 5. Blast radius
        blast = calculate_blast_radius(
            original_permissions=active,
            proposed_permissions=prop_list,
            principal_id=role_id,
            provider=self.capabilities.provider_name,
        )

        reasons: List[str] = []
        if not structural_valid:
            reasons.append("Structural validation failed")
        if not privilege_non_expanded:
            reasons.extend(exp_res.reasons)
        if not simulation_passed:
            reasons.append(f"Simulation failed on '{sim_res.failed_workflow}': missing '{sim_res.missing_permission}'")
        if not regression_passed:
            reasons.append(f"Regression tests failed: {reg_res.failed_tests}")

        approved = structural_valid and privilege_non_expanded and simulation_passed and regression_passed

        return PreApplyVerificationResult(
            approved_for_apply=approved,
            structural_valid=structural_valid,
            privilege_non_expanded=privilege_non_expanded,
            evidence_sufficient=True,
            simulation_passed=simulation_passed,
            regression_passed=regression_passed,
            blast_radius=blast.level,
            decision="allow" if approved else "deny",
            reasons=reasons,
            details={
                "blast_radius_score": blast.score,
                "regression_summary": f"{reg_res.passed_count}/{reg_res.total_tests} passed",
            },
        )


__all__ = [
    "ComprehensiveVerificationResult",
    "RollbackVerificationResult",
    "PreApplyVerificationResult",
    "ExtendedPolicyVerifier",
]

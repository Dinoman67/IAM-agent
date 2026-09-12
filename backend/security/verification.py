"""Multi-dimensional post-remediation verification authority."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.environment.loader import IAMEnvironment
from backend.environment.simulator import PolicySimulator
from backend.environment.verifier import PolicyVerifier
from backend.providers.capabilities import ProviderCapabilities, AWS_CAPABILITIES


class ComprehensiveVerificationResult(BaseModel):
    """Detailed verification outcome spanning functional, security, structural, and provider checks."""

    passed: bool
    functional_passed: bool
    security_passed: bool
    structural_passed: bool
    provider_passed: bool
    checks: Dict[str, bool] = Field(default_factory=dict)
    details: List[str] = Field(default_factory=list)
    should_rollback: bool = False


class ExtendedPolicyVerifier:
    """Comprehensive verifier executing independent post-apply validation across providers."""

    def __init__(
        self,
        env: IAMEnvironment,
        capabilities: Optional[ProviderCapabilities] = None,
    ) -> None:
        self.env = env
        self.capabilities = capabilities or AWS_CAPABILITIES
        self.base_verifier = PolicyVerifier(env)

    def verify_remediation(
        self,
        role_id: str,
        expected_permissions: Optional[List[str]] = None,
        provider: Optional[str] = None,
    ) -> ComprehensiveVerificationResult:
        """Executes full suite of post-change verifications with provider awareness."""
        base_res = self.base_verifier.verify(role_id)
        role = self.env.get_role(role_id)

        if not role:
            return ComprehensiveVerificationResult(
                passed=False,
                functional_passed=False,
                security_passed=False,
                structural_passed=False,
                provider_passed=False,
                checks={"role_exists": False},
                details=[f"Role '{role_id}' not found."],
                should_rollback=True,
            )

        active_perms = role.active_permissions()
        details = list(base_res.details)
        checks = dict(base_res.checks)

        # 1. Functional check (workflows)
        functional_passed = base_res.checks.get("workflows_passed", False)

        # 2. Security check (protected resources)
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

        passed = functional_passed and security_passed and structural_passed and provider_passed

        # Flag for automated rollback if functional workflows failed after apply
        should_rollback = not functional_passed or not security_passed

        return ComprehensiveVerificationResult(
            passed=passed,
            functional_passed=functional_passed,
            security_passed=security_passed,
            structural_passed=structural_passed,
            provider_passed=provider_passed,
            checks=checks,
            details=details,
            should_rollback=should_rollback,
        )


__all__ = [
    "ComprehensiveVerificationResult",
    "ExtendedPolicyVerifier",
]

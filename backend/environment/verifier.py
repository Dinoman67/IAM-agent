"""Deterministic verification layer for policy correctness and security invariants."""

from __future__ import annotations

from typing import Dict, List

from backend.environment.loader import IAMEnvironment
from backend.environment.simulator import PolicySimulator
from backend.models.schemas import VerificationResult


class PolicyVerifier:
    """Independent verification authority checking operational and security invariants."""

    def __init__(self, environment: IAMEnvironment) -> None:
        self.env = environment
        self.simulator = PolicySimulator(environment)

    def verify(self, role_id: str) -> VerificationResult:
        """Deterministically evaluates the active policy of a role.
        The LLM/Reasoner is NEVER the authority for this check.
        """
        role = self.env.get_role(role_id)
        if not role:
            return VerificationResult(
                passed=False,
                checks={"role_exists": False},
                details=[f"Role '{role_id}' does not exist."],
            )

        active_perms = role.active_permissions()
        details: List[str] = []
        checks: Dict[str, bool] = {}

        # 1. Operational Invariant: Required service workflows still succeed
        sim_result = self.simulator.simulate(role_id, active_perms)
        checks["workflows_passed"] = sim_result.success
        if sim_result.success:
            details.append("Workflows verification: PASS (all required workflows function)")
        else:
            details.append(f"Workflows verification: FAIL ({sim_result.details})")

        # 2. Security Invariant: Protected resources remain isolated
        exposed_resources: List[str] = []
        for resource in self.env.data.resources:
            if resource.is_protected:
                for perm in resource.required_permissions:
                    if PolicySimulator.is_action_allowed(perm, active_perms):
                        exposed_resources.append(f"{resource.id} ({resource.arn}) via '{perm}'")

        checks["protected_resources_isolated"] = len(exposed_resources) == 0
        if checks["protected_resources_isolated"]:
            details.append("Protected resource isolation: PASS (sensitive resources shielded)")
        else:
            details.append(
                f"Protected resource isolation: FAIL (exposed: {', '.join(exposed_resources)})"
            )

        # 3. State Invariant: Policy change actually applied
        has_new_version = role.current_version != "v1" and len(role.policy_versions) > 1
        checks["policy_applied"] = has_new_version
        if has_new_version:
            details.append(f"Policy applied: PASS (active version {role.current_version})")
        else:
            details.append(f"Policy applied: FAIL (still on initial version {role.current_version})")

        # 4. Mitigation Invariant: Excess permissions were reduced
        initial_version = role.policy_versions[0] if role.policy_versions else None
        initial_count = len(initial_version.permissions) if initial_version else 0
        current_count = len(active_perms)
        is_reduced = current_count < initial_count
        checks["excess_permissions_reduced"] = is_reduced
        if is_reduced:
            details.append(
                f"Excess permissions reduction: PASS (reduced from {initial_count} to {current_count} permissions)"
            )
        else:
            details.append(
                f"Excess permissions reduction: FAIL (initial {initial_count} vs active {current_count})"
            )

        overall_passed = all(checks.values())
        return VerificationResult(
            passed=overall_passed,
            checks=checks,
            details=details,
        )

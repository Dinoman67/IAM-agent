"""Deterministic Security Kernel and Authorization Gate.

The Security Kernel is the authoritative control boundary. The AI proposes,
but the deterministic Kernel validates, authorizes, or rejects changes.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

from backend.environment.loader import IAMEnvironment
from backend.environment.simulator import PolicySimulator
from backend.providers.capabilities import ProviderCapabilities, AWS_CAPABILITIES

GateDecision = Literal["allow", "deny", "escalate"]


class SecurityGateResult(BaseModel):
    """Authoritative result returned by the Security Kernel gate."""

    decision: GateDecision = Field(..., description="'allow', 'deny', or 'escalate'")
    reason_codes: List[str] = Field(default_factory=list)
    required_approval: bool = Field(default=False)
    risk_level: str = Field(default="low")
    confidence: float = Field(default=1.0)
    details: Dict[str, Any] = Field(default_factory=dict)


class SecurityKernel:
    """Independent deterministic authority governing IAM mutations across all cloud providers."""

    # Permissions that cannot be granted or made overly permissive
    PROTECTED_PERMISSIONS = {"iam:*", "*", "sts:AssumeRole*"}

    def __init__(
        self,
        env: IAMEnvironment,
        capabilities: Optional[ProviderCapabilities] = None,
        min_confidence_for_apply: float = 0.85,
    ) -> None:
        self.env = env
        self.capabilities = capabilities or AWS_CAPABILITIES
        self.min_confidence = min_confidence_for_apply

    def evaluate_proposal(
        self,
        role_id: str,
        proposed_permissions: List[str],
        planned_policy_version: str,
        confidence: float,
        simulation_result: Optional[Dict[str, Any]] = None,
        risk_level: str = "medium",
        provider: Optional[str] = None,
    ) -> SecurityGateResult:
        """Deterministically evaluates if proposed policy change is authorized for application."""
        role = self.env.get_role(role_id)
        if not role:
            return SecurityGateResult(
                decision="deny",
                reason_codes=["role_not_found"],
                required_approval=True,
                risk_level="critical",
                confidence=1.0,
                details={"error": f"Role '{role_id}' does not exist."},
            )

        reason_codes: List[str] = []
        details: Dict[str, Any] = {}

        # 1. Provider Mismatch Protection
        target_provider = self.capabilities.provider_name.lower()
        if provider and provider.lower() != target_provider:
            reason_codes.append(f"provider_mismatch:{provider}_vs_{target_provider}")
            details["provider_mismatch"] = {
                "source_provider": provider,
                "target_provider": target_provider,
                "reason": "Cannot apply changes destined for another cloud provider environment",
            }

        # 2. Stale State Protection (Optimistic Concurrency)
        if role.current_version != planned_policy_version:
            reason_codes.append("stale_state_detected")
            details["stale_state"] = {
                "expected_version": planned_policy_version,
                "current_version": role.current_version,
            }

        # 3. Privilege Expansion Check (least-privilege invariant: proposed must not silently grant new unneeded permissions)
        original_perms = set(role.active_permissions())
        proposed_perms_set = set(proposed_permissions)
        expansion = proposed_perms_set - original_perms
        if expansion:
            for p in sorted(list(expansion)):
                reason_codes.append(f"unauthorized_privilege_expansion:{p}")
            details["privilege_expansion"] = list(expansion)

        # 4. Provider Capabilities Check
        if not self.capabilities.supports_policy_simulation and simulation_result is None:
            reason_codes.append("unsupported_capability_no_simulation")
        if not self.capabilities.supports_policy_versioning:
            reason_codes.append("unsupported_capability_no_versioning")
        if not self.capabilities.supports_rollback:
            # If rollback is not supported by provider, human approval is mandatory
            reason_codes.append("unsupported_capability_no_rollback")

        # 5. Protected Invariants Check: Are protected permissions improperly granted or retained?
        for p in proposed_permissions:
            if p in self.PROTECTED_PERMISSIONS:
                # Retaining admin wildcard permissions in least-privilege proposal is flagged
                reason_codes.append(f"protected_permission_retained:{p}")

        # 6. Sensitive Resources Isolation Check
        for resource in self.env.data.resources:
            if resource.is_protected:
                for perm in resource.required_permissions:
                    if PolicySimulator.is_action_allowed(perm, proposed_permissions):
                        reason_codes.append(f"sensitive_resource_exposed:{resource.id}")

        # 7. Simulation Verification Check
        if simulation_result is not None:
            if not simulation_result.get("success", False):
                reason_codes.append("simulation_failed")
                details["failed_workflow"] = simulation_result.get("failed_workflow")
                details["missing_permission"] = simulation_result.get("missing_permission")
        else:
            # Mutation without simulation is denied if simulation is supported
            if self.capabilities.supports_policy_simulation:
                reason_codes.append("unsimulated_change_denied")

        # 8. Confidence and Risk Gating
        if confidence < self.min_confidence:
            reason_codes.append("insufficient_confidence")

        # Gate Evaluation Logic
        # Deny conditions (violations that cannot be bypassed even with escalation)
        hard_deny_codes = [
            c for c in reason_codes
            if "stale_state" in c
            or "simulation_failed" in c
            or "sensitive_resource_exposed" in c
            or "unsimulated_change" in c
            or "provider_mismatch" in c
            or "unauthorized_privilege_expansion" in c
        ]

        if hard_deny_codes:
            return SecurityGateResult(
                decision="deny",
                reason_codes=reason_codes,
                required_approval=True,
                risk_level="high",
                confidence=confidence,
                details=details,
            )

        # Escalation conditions (requires human sign-off)
        escalate_codes = [
            c for c in reason_codes
            if "unsupported_capability" in c
            or "insufficient_confidence" in c
            or "protected_permission" in c
        ]

        if escalate_codes or risk_level in ["high", "critical"] or confidence < 0.90:
            return SecurityGateResult(
                decision="escalate",
                reason_codes=reason_codes,
                required_approval=True,
                risk_level=risk_level,
                confidence=confidence,
                details=details,
            )

        # Allow: Low/Medium Risk + High Confidence + Simulated + Fresh State
        return SecurityGateResult(
            decision="allow",
            reason_codes=[],
            required_approval=False,
            risk_level=risk_level,
            confidence=confidence,
            details={"approved": True},
        )

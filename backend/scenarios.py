"""Shared scenario reasoners — single source of truth for CLI (main.py) and API (backend/api/main.py).

Fix #4: previously 6 scenario reasoners were duplicated (~400 lines) in both entrypoints.
Import from here instead.
"""

from __future__ import annotations

from typing import Any, Optional

from backend.agent.decisions import AgentDecision
from backend.agent.reasoner import DeterministicReasoner


class GCPSimulationAttemptReasoner:
    """Attempt inspect + simulate on GCP (truthfully escalates: simulation unsupported)."""

    def __init__(self, role_id: str = "PaymentServiceRole") -> None:
        self.role_id = role_id
        self.step = 0

    def decide(self, state, **kwargs) -> AgentDecision:
        self.step += 1
        if self.step == 1:
            return AgentDecision(
                decision_type="tool_call",
                tool_name="inspect_role",
                arguments={"role_id": self.role_id},
                reason="Inspect active role definition on GCP",
            )
        elif self.step == 2:
            return AgentDecision(
                decision_type="tool_call",
                tool_name="simulate_change",
                arguments={
                    "role_id": self.role_id,
                    "proposed_permissions": ["s3:GetObject"],
                },
                reason="Attempting pre-commit simulation on GCP adapter",
                metadata={"candidate_phase": "initial_proposal"},
            )
        return AgentDecision(decision_type="abort", reason="Sequence complete")


class CrossProviderMismatchReasoner:
    """Attempt cross-cloud mutation (Security Kernel must DENY with provider_mismatch)."""

    def __init__(self, role_id: str = "PaymentServiceRole") -> None:
        self.role_id = role_id

    def decide(self, state, **kwargs) -> AgentDecision:
        return AgentDecision(
            decision_type="tool_call",
            tool_name="apply_policy_change",
            arguments={
                "role_id": self.role_id,
                "new_permissions": ["s3:GetObject"],
                "reason": "Applying Azure role assignment to AWS environment",
            },
            reason="Cross-provider mutation request",
        )


class SensitiveAdminRemovalReasoner(DeterministicReasoner):
    """Attempt unsafe removal of protected admin action (must BLOCK)."""

    def __init__(self, target_role_id: str = "PaymentServiceRole") -> None:
        super().__init__(target_role_id=target_role_id)
        self.step = 0

    def decide(self, state, **kwargs) -> AgentDecision:
        self.step += 1
        if self.step == 1:
            return AgentDecision(
                decision_type="tool_call",
                tool_name="get_role",
                arguments={"role_id": self.default_role_id},
                reason="Inspect role and discover active permissions",
            )
        elif self.step == 2:
            return AgentDecision(
                decision_type="tool_call",
                tool_name="apply_policy_change",
                arguments={
                    "role_id": self.default_role_id,
                    "remove_permissions": ["iam:CreateRole"],
                    "reason": "Unsafe removal of sensitive administrative action",
                },
                reason="Proposing to mutate protected administrative action",
            )
        return AgentDecision(decision_type="abort", reason="Sequence exhausted")


class BrokenPolicyReasoner(DeterministicReasoner):
    """Deliberately apply flawed policy (drops kms:Decrypt) to trigger rollback."""

    def __init__(self, target_role_id: str = "PaymentServiceRole") -> None:
        super().__init__(target_role_id=target_role_id)
        self.step = 0

    def decide(self, state, **kwargs) -> AgentDecision:
        self.step += 1
        if self.step == 1:
            return AgentDecision(
                decision_type="tool_call",
                tool_name="get_role",
                arguments={"role_id": self.default_role_id},
                reason="Inspect active role definition",
            )
        elif self.step == 2:
            return AgentDecision(
                decision_type="tool_call",
                tool_name="apply_policy_change",
                arguments={
                    "role_id": self.default_role_id,
                    "remove_permissions": ["kms:Decrypt"],
                    "reason": "Faulty least-privilege apply lacking KMS dependency",
                },
                reason="Apply flawed policy mutation to live environment",
            )
        elif self.step == 3:
            return AgentDecision(
                decision_type="tool_call",
                tool_name="verify_required_access",
                arguments={"role_id": self.default_role_id},
                reason="Execute live post-apply functional and regression verification",
            )
        return AgentDecision(decision_type="abort", reason="Sequence complete")


class StaleStateReasoner(DeterministicReasoner):
    """Simulate optimistic-concurrency recovery (stale v1 -> refresh v2 -> apply v3).

    The out-of-band concurrent write is injected via ``on_step2`` callback so the
    class stays environment-agnostic and reusable from CLI and API.
    """

    def __init__(self, target_role_id: str = "PaymentServiceRole", on_step2=None) -> None:
        super().__init__(target_role_id=target_role_id)
        self.step = 0
        self._on_step2 = on_step2

    def decide(self, state, **kwargs) -> AgentDecision:
        self.step += 1
        rid = self.default_role_id
        if self.step == 1:
            return AgentDecision(
                decision_type="tool_call",
                tool_name="get_role",
                arguments={"role_id": rid},
                reason="Inspect active role definition (version v1)",
            )
        elif self.step == 2:
            if callable(self._on_step2):
                self._on_step2()
            return AgentDecision(
                decision_type="tool_call",
                tool_name="apply_policy_change",
                arguments={
                    "role_id": rid,
                    "remove_permissions": ["ec2:*", "iam:*"],
                    "reason": "Attempt apply based on stale baseline version v1",
                },
                reason="Proposing change unaware of concurrent update",
            )
        elif self.step == 3:
            return AgentDecision(
                decision_type="tool_call",
                tool_name="simulate_policy",
                arguments={
                    "role_id": rid,
                    "proposed_permissions": ["s3:GetObject", "s3:PutObject", "kms:Decrypt", "cloudwatch:PutMetricData"],
                },
                reason="Simulate least-privilege permissions against refreshed state",
                metadata={
                    "candidate_phase": "initial_proposal",
                    "proposed_permissions": ["s3:GetObject", "s3:PutObject", "kms:Decrypt", "cloudwatch:PutMetricData"],
                    "remove_permissions": ["ec2:*", "iam:*"],
                },
            )
        elif self.step == 4:
            return AgentDecision(
                decision_type="tool_call",
                tool_name="apply_policy_change",
                arguments={
                    "role_id": rid,
                    "remove_permissions": ["ec2:*", "iam:*", "dynamodb:*"],
                    "reason": "Apply clean least-privilege policy against refreshed version v2",
                },
                reason="Apply policy change with refreshed version v2",
            )
        elif self.step == 5:
            return AgentDecision(
                decision_type="tool_call",
                tool_name="verify_required_access",
                arguments={"role_id": rid},
                reason="Verify required access",
            )
        elif self.step == 6:
            return AgentDecision(
                decision_type="complete",
                reason="Successfully remediated against updated concurrent policy state",
            )
        return AgentDecision(decision_type="abort", reason="Sequence complete")


def normalize_scenario(name: Optional[str]) -> str:
    """Normalize scenario aliases to canonical keys."""
    s = (name or "aws").lower().replace("-", "_")
    aliases = {
        "payment": "aws",
        "unsupported_gcp": "unsupported_gcp",
        "provider_mismatch": "provider_mismatch",
        "safety_block": "safety_block",
        "rollback": "rollback",
        "verification_rollback": "rollback",
        "stale_state": "stale_state",
    }
    return aliases.get(s, s)


__all__ = [
    "GCPSimulationAttemptReasoner",
    "CrossProviderMismatchReasoner",
    "SensitiveAdminRemovalReasoner",
    "BrokenPolicyReasoner",
    "StaleStateReasoner",
    "normalize_scenario",
]

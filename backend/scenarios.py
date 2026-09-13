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


GCP_DEMO_ROLE_ID = "BillingExportSA"

GCP_PRUNED_PERMISSIONS = [
    "storage.objects.get",
    "storage.objects.create",
    "cloudkms.cryptoKeyDecrypter",
    "logging.logEntries.create",
]

GCP_V1_PERMISSIONS = GCP_PRUNED_PERMISSIONS + [
    "compute.instances.delete",
    "resourcemanager.projects.setIamPolicy",
]


class GCPDeterministicReasoner:
    """Deterministic closed-loop reasoner for the GCP billing-export story.

    Mirrors the AWS arc with GCP names: observe -> audit -> flag unlogged ->
    local-evaluate naive removal (FAILS on CMEK decrypter) -> discover
    CloudStorage -> CloudKMS coupling -> replan keeping the decrypter ->
    re-evaluate -> apply -> verify -> complete. Uses evaluate_local_policy
    (sandbox local evaluation) instead of native simulation.
    """

    def __init__(self, target_role_id: str = GCP_DEMO_ROLE_ID) -> None:
        self.default_role_id = target_role_id

    def _resolve_role_id(self, state) -> str:
        return state.current_role or self.default_role_id

    def decide(self, state, **kwargs) -> AgentDecision:
        role_id = self._resolve_role_id(state)
        if not state.current_role:
            state.current_role = role_id
        executed = [c.get("tool_name") for c in state.tool_calls]

        if "get_role" not in executed and "inspect_role" not in executed:
            return AgentDecision(
                decision_type="tool_call",
                tool_name="get_role",
                arguments={"role_id": role_id},
                reason=f"Inspecting GCP bindings and granted permissions for '{role_id}'.",
                confidence=1.0,
            )

        if "get_access_history" not in executed:
            return AgentDecision(
                decision_type="tool_call",
                tool_name="get_access_history",
                arguments={"role_id": role_id},
                reason=f"Auditing Cloud Audit Logs for '{role_id}' to discover active usage.",
                confidence=1.0,
            )

        if "find_unused_permissions" not in executed:
            return AgentDecision(
                decision_type="tool_call",
                tool_name="find_unused_permissions",
                arguments={"role_id": role_id},
                reason=f"Cross-referencing granted permissions against observed audit logs for '{role_id}'.",
                confidence=0.95,
            )

        sim_count = executed.count("evaluate_local_policy")
        unused = state.observed_evidence.get("unused_permissions", [])

        if sim_count == 0:
            role_info = state.observed_evidence.get("role", {})
            active = role_info.get("active_permissions", [])
            proposed = [p for p in active if p not in unused]
            return AgentDecision(
                decision_type="tool_call",
                tool_name="evaluate_local_policy",
                arguments={"role_id": role_id, "proposed_permissions": proposed, "provider": "gcp"},
                reason=(
                    f"Candidate excessive bindings identified: {unused}. "
                    "Running local evaluation of the removal impact."
                ),
                confidence=0.75,
                metadata={
                    "candidate_phase": "initial_proposal",
                    "remove_permissions": unused,
                    "proposed_permissions": proposed,
                },
            )

        if sim_count == 1:
            last_sim = state.simulation_results[-1] if state.simulation_results else {}
            if not last_sim.get("success", True) and "get_service_dependencies" not in executed:
                missing = last_sim.get("missing_permission", "cloudkms.cryptoKeyDecrypter")
                return AgentDecision(
                    decision_type="tool_call",
                    tool_name="get_service_dependencies",
                    arguments={"service": "CheckoutService"},
                    reason=(
                        f"Local evaluation FAILED! Missing permission detected: '{missing}'. "
                        "Investigating transitive service dependencies for CheckoutService."
                    ),
                    confidence=0.90,
                    metadata={"investigating_permission": missing},
                )

        if "get_service_dependencies" in executed and sim_count == 1:
            revised_remove = [p for p in unused if p.lower() != "cloudkms.cryptokeydecrypter"]
            role_info = state.observed_evidence.get("role", {})
            active = role_info.get("active_permissions", [])
            revised = [p for p in active if p not in revised_remove]
            return AgentDecision(
                decision_type="tool_call",
                tool_name="evaluate_local_policy",
                arguments={"role_id": role_id, "proposed_permissions": revised, "provider": "gcp"},
                reason=(
                    "Discovered dependency: CheckoutService -> CloudStorage -> CloudKMS requires "
                    f"'cloudkms.cryptoKeyDecrypter' for CMEK decryption. Replanning: retaining it and "
                    f"removing only dangerous grants: {revised_remove}."
                ),
                confidence=0.95,
                metadata={
                    "candidate_phase": "replan_proposal",
                    "retained_dependencies": ["cloudkms.cryptoKeyDecrypter"],
                    "remove_permissions": revised_remove,
                    "proposed_permissions": revised,
                },
            )

        if "apply_policy_change" not in executed:
            last_sim = state.simulation_results[-1] if state.simulation_results else {}
            if last_sim.get("success", False):
                revised_remove = [p for p in unused if p.lower() != "cloudkms.cryptokeydecrypter"]
                return AgentDecision(
                    decision_type="tool_call",
                    tool_name="apply_policy_change",
                    arguments={
                        "role_id": role_id,
                        "remove_permissions": revised_remove,
                        "reason": "Autonomous least-privilege mitigation preserving critical CMEK decryption binding.",
                    },
                    reason=(
                        "Local evaluation passed for revised bindings. Applying least-privilege changes "
                        f"for '{role_id}'."
                    ),
                    confidence=0.98,
                )
            return AgentDecision(
                decision_type="abort",
                reason=f"Local evaluation failed unexpectedly without a replanning path: {last_sim}",
                confidence=0.99,
            )

        if "verify_required_access" not in executed:
            return AgentDecision(
                decision_type="tool_call",
                tool_name="verify_required_access",
                arguments={"role_id": role_id},
                reason=f"Bindings updated. Executing independent verification layer for '{role_id}'.",
                confidence=1.0,
            )

        verification = state.verification_result or {}
        if verification.get("passed", False):
            return AgentDecision(
                decision_type="complete",
                reason=(
                    "Least-privilege mitigation successfully verified on GCP. "
                    "All export workflows operational and excessive bindings revoked."
                ),
                confidence=1.0,
                metadata={"status": "success"},
            )
        return AgentDecision(
            decision_type="abort",
            reason=f"Verification failed: {verification.get('details', [])}",
            confidence=1.0,
            metadata={"status": "verification_failed"},
        )


class GCPRecoveryReasoner:
    """Honest GCP recovery: no atomic rollback exists, so recovery re-binds policy.

    Applies a flawed binding (drops the CMEK decrypter), watches verification
    fail, evaluates the correct least-privilege set locally, then re-binds it
    through the standard apply path and verifies again.
    """

    def __init__(self, target_role_id: str = GCP_DEMO_ROLE_ID) -> None:
        self.default_role_id = target_role_id

    def decide(self, state, **kwargs) -> AgentDecision:
        rid = state.current_role or self.default_role_id
        if not state.current_role:
            state.current_role = rid
        calls = [c.get("tool_name") for c in state.tool_calls]
        # Count only EXECUTED applies: a kernel stale-deny consumes the decision
        # without recording a tool result, so retries must not advance the plan.
        applied_ok = {
            r.get("step") for r in (state.tool_results or [])
            if r.get("tool_name") in ("apply_policy_change", "apply_change") and r.get("success")
        }
        n_apply = len(applied_ok)
        n_verify = sum(1 for t in calls if t in ("verify_required_access", "verify_change"))
        n_eval = sum(1 for t in calls if t == "evaluate_local_policy")
        ver = state.verification_result or {}

        if "get_role" not in calls and "inspect_role" not in calls:
            return AgentDecision(
                decision_type="tool_call", tool_name="get_role",
                arguments={"role_id": rid}, reason="Inspect active GCP bindings.",
            )
        if n_apply == 0:
            return AgentDecision(
                decision_type="tool_call", tool_name="apply_policy_change",
                arguments={
                    "role_id": rid,
                    "remove_permissions": ["cloudkms.cryptoKeyDecrypter"],
                    "reason": "Faulty least-privilege apply lacking CMEK dependency",
                },
                reason="Apply flawed binding mutation to demonstrate recovery",
            )
        if n_verify == 0:
            return AgentDecision(
                decision_type="tool_call", tool_name="verify_required_access",
                arguments={"role_id": rid}, reason="Execute post-apply verification",
            )
        if not ver.get("passed", False) and n_apply == 1 and n_eval == 0:
            return AgentDecision(
                decision_type="tool_call", tool_name="evaluate_local_policy",
                arguments={"role_id": rid, "proposed_permissions": list(GCP_PRUNED_PERMISSIONS), "provider": "gcp"},
                reason="Verification failed. Locally evaluating the correct least-privilege set before re-binding.",
                confidence=0.95,
                metadata={
                    "candidate_phase": "replan_proposal",
                    "retained_dependencies": ["cloudkms.cryptoKeyDecrypter"],
                    "remove_permissions": ["compute.instances.delete", "resourcemanager.projects.setIamPolicy"],
                    "proposed_permissions": list(GCP_PRUNED_PERMISSIONS),
                },
            )
        if n_apply == 1:
            return AgentDecision(
                decision_type="tool_call", tool_name="apply_policy_change",
                arguments={
                    "role_id": rid,
                    "new_permissions": list(GCP_PRUNED_PERMISSIONS),
                    "reason": "Recovery: re-bind correct least-privilege policy after failed verification",
                },
                reason="Re-binding prior correct bindings through the standard apply path (no atomic rollback on GCP)",
                confidence=0.98,
            )
        if n_verify == 1:
            return AgentDecision(
                decision_type="tool_call", tool_name="verify_required_access",
                arguments={"role_id": rid}, reason="Verify recovered bindings",
            )
        if ver.get("passed", False):
            return AgentDecision(
                decision_type="complete",
                reason="GCP recovery complete: correct bindings re-bound and independently verified.",
                confidence=1.0, metadata={"status": "success"},
            )
        return AgentDecision(decision_type="abort", reason=f"Recovery verification failed: {ver.get('details', [])}")


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
    "GCPDeterministicReasoner",
    "GCPRecoveryReasoner",
    "GCP_DEMO_ROLE_ID",
    "GCP_PRUNED_PERMISSIONS",
    "GCP_V1_PERMISSIONS",
    "normalize_scenario",
]

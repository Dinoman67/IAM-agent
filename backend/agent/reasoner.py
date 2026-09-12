"""Reasoner protocol and deterministic state machine implementation for Phase 1."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, Protocol, runtime_checkable
from pydantic import BaseModel, Field

from backend.state.models import AgentState


class Decision(BaseModel):
    """Structured decision output from the Reasoner to the Controller."""

    action_type: Literal["call_tool", "complete", "fail"] = Field(
        ..., description="Action category: 'call_tool', 'complete', or 'fail'"
    )
    tool_name: Optional[str] = Field(default=None, description="Name of the tool to invoke")
    tool_args: Optional[Dict[str, Any]] = Field(
        default=None, description="Arguments to pass to the tool"
    )
    thought: str = Field(default="", description="Internal reasoning chain or explanation")
    metadata: Dict[str, Any] = Field(default_factory=dict)


@runtime_checkable
class Reasoner(Protocol):
    """Abstract reasoner interface. Can be backed by deterministic logic or an LLM."""

    def decide(self, state: AgentState) -> Decision:
        """Produce the next agent action based on current state."""
        ...


class DeterministicReasoner:
    """Deterministic closed-loop reasoner for Phase 1 demonstration.
    
    Implements the observe -> propose -> simulate -> failure -> discover dependency 
    -> replan -> simulate -> apply -> verify cycle.
    """

    def __init__(self, target_role_id: str = "PaymentServiceRole") -> None:
        self.default_role_id = target_role_id

    def _resolve_role_id(self, state: AgentState) -> str:
        if state.current_role:
            return state.current_role
        # Extract from goal if mentioned, else default
        if "paymentservicerole" in state.goal.lower():
            return "PaymentServiceRole"
        return self.default_role_id

    def decide(self, state: AgentState) -> Decision:
        role_id = self._resolve_role_id(state)
        if not state.current_role:
            state.current_role = role_id

        # Track tool executions
        executed_tools = [c.get("tool_name") for c in state.tool_calls]

        # 1. Inspect the role
        if "get_role" not in executed_tools:
            return Decision(
                action_type="call_tool",
                tool_name="get_role",
                tool_args={"role_id": role_id},
                thought=f"Inspecting role configuration and active permissions for '{role_id}'.",
            )

        # 2. Inspect access history
        if "get_access_history" not in executed_tools:
            return Decision(
                action_type="call_tool",
                tool_name="get_access_history",
                tool_args={"role_id": role_id},
                thought=f"Auditing CloudTrail access history for role '{role_id}' to discover active usage.",
            )

        # 3. Identify candidate excessive permissions
        if "find_unused_permissions" not in executed_tools:
            return Decision(
                action_type="call_tool",
                tool_name="find_unused_permissions",
                tool_args={"role_id": role_id},
                thought=f"Cross-referencing granted permissions against observed access logs for '{role_id}'.",
            )

        # 4. First simulation (naive removal of all unlogged permissions)
        # Check if we have run simulation yet
        sim_count = executed_tools.count("simulate_policy")
        unused = state.observed_evidence.get("unused_permissions", [])

        if sim_count == 0:
            # Naive proposal: remove all unused permissions
            # Note: in PaymentServiceRole, unused includes kms:Decrypt because kms is a hidden downstream dependency
            role_info = state.observed_evidence.get("role", {})
            active_perms = role_info.get("active_permissions", [])
            proposed = [p for p in active_perms if p not in unused]

            return Decision(
                action_type="call_tool",
                tool_name="simulate_policy",
                tool_args={
                    "role_id": role_id,
                    "proposed_permissions": proposed,
                },
                thought=(
                    f"Candidate excessive permissions identified: {unused}. "
                    f"Proposing removal of all {len(unused)} unlogged permissions and simulating impact."
                ),
                metadata={
                    "candidate_phase": "initial_proposal",
                    "remove_permissions": unused,
                    "proposed_permissions": proposed,
                },
            )

        # 5. Check first simulation result
        # If first simulation failed on kms:Decrypt and we haven't checked service dependencies
        if sim_count == 1:
            last_sim = state.simulation_results[-1] if state.simulation_results else {}
            if not last_sim.get("success", True) and "get_service_dependencies" not in executed_tools:
                missing_perm = last_sim.get("missing_permission", "kms:Decrypt")
                return Decision(
                    action_type="call_tool",
                    tool_name="get_service_dependencies",
                    tool_args={"service": "PaymentService"},
                    thought=(
                        f"Initial simulation FAILED! Missing permission detected: '{missing_perm}'. "
                        "Investigating transitive service dependencies for PaymentService."
                    ),
                    metadata={"investigating_permission": missing_perm},
                )

        # 6. Replan and simulate revised policy
        # If we have discovered dependencies and sim_count is still 1
        if "get_service_dependencies" in executed_tools and sim_count == 1:
            # Revised proposal: retain kms:Decrypt! Remove only dangerous unused wildcards
            # ec2:*, iam:*, dynamodb:*
            revised_remove = [p for p in unused if p.lower() != "kms:decrypt"]
            role_info = state.observed_evidence.get("role", {})
            active_perms = role_info.get("active_permissions", [])
            revised_proposed = [p for p in active_perms if p not in revised_remove]

            return Decision(
                action_type="call_tool",
                tool_name="simulate_policy",
                tool_args={
                    "role_id": role_id,
                    "proposed_permissions": revised_proposed,
                },
                thought=(
                    "Discovered dependency: PaymentService -> S3 -> KMS requires 'kms:Decrypt' for SSE decryption. "
                    f"Replanning: Retaining 'kms:Decrypt' and proposing removal only of excessive wildcards: {revised_remove}."
                ),
                metadata={
                    "candidate_phase": "replan_proposal",
                    "retained_dependencies": ["kms:Decrypt"],
                    "remove_permissions": revised_remove,
                    "proposed_permissions": revised_proposed,
                },
            )

        # 7. Apply revised policy if simulation passed
        if "apply_policy_change" not in executed_tools:
            last_sim = state.simulation_results[-1] if state.simulation_results else {}
            if last_sim.get("success", False):
                revised_remove = [p for p in unused if p.lower() != "kms:decrypt"]
                return Decision(
                    action_type="call_tool",
                    tool_name="apply_policy_change",
                    tool_args={
                        "role_id": role_id,
                        "remove_permissions": revised_remove,
                        "reason": "Autonomous least-privilege mitigation preserving critical KMS decryption dependency.",
                    },
                    thought=(
                        "Simulation passed for revised policy. Applying least-privilege changes "
                        f"to create new policy version for '{role_id}'."
                    ),
                )
            else:
                return Decision(
                    action_type="fail",
                    thought=f"Simulation failed unexpectedly without an available replanning path: {last_sim}",
                )

        # 8. Deterministic verification
        if "verify_required_access" not in executed_tools:
            return Decision(
                action_type="call_tool",
                tool_name="verify_required_access",
                tool_args={"role_id": role_id},
                thought=f"Policy version created. Executing independent verification layer for '{role_id}'.",
            )

        # 9. Complete workflow
        verification = state.verification_result or {}
        if verification.get("passed", False):
            return Decision(
                action_type="complete",
                thought=(
                    "Least-privilege mitigation successfully verified. "
                    "All application workflows operational and excessive privileges revoked."
                ),
                metadata={"status": "success"},
            )
        else:
            return Decision(
                action_type="fail",
                thought=f"Verification failed: {verification.get('details', [])}",
                metadata={"status": "verification_failed"},
            )

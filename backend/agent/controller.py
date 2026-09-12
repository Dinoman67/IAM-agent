"""Autonomous Agent Controller orchestrating the observe-plan-simulate-replan-verify loop."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from backend.agent.budgets import AgentBudget, BudgetTracker
from backend.agent.planner import AgentPlan
from backend.agent.reasoner import Reasoner
from backend.environment.loader import IAMEnvironment
from backend.providers.capabilities import AWS_CAPABILITIES, ProviderCapabilities
from backend.security.diff import compute_policy_diff
from backend.security.kernel import SecurityKernel
from backend.security.verification import ExtendedPolicyVerifier
from backend.state.models import AgentState, AuditEvent
from backend.state.store import InMemoryStateStore, StateStore
from backend.tools.registry import ToolRegistry


class AgentController:
    """Core controller coordinating reasoner decisions, deterministic tools, security gate, and audit logs."""

    def __init__(
        self,
        reasoner: Reasoner,
        tool_registry: ToolRegistry,
        state_store: Optional[StateStore] = None,
        event_callback: Optional[Callable[[AuditEvent], None]] = None,
        budget: Optional[AgentBudget] = None,
        security_kernel: Optional[SecurityKernel] = None,
        capabilities: Optional[ProviderCapabilities] = None,
        environment: Optional[IAMEnvironment] = None,
    ) -> None:
        self.reasoner = reasoner
        self.tools = tool_registry
        self.state_store = state_store or InMemoryStateStore()
        self.event_callback = event_callback
        self.budget = budget or AgentBudget()
        self.capabilities = capabilities or AWS_CAPABILITIES
        self.env = environment

        # Security Kernel authority
        if security_kernel:
            self.security_kernel = security_kernel
        elif self.env:
            self.security_kernel = SecurityKernel(self.env, capabilities=self.capabilities)
        else:
            self.security_kernel = None

        if self.env:
            self.extended_verifier = ExtendedPolicyVerifier(self.env, capabilities=self.capabilities)
        else:
            self.extended_verifier = None

    def _emit_event(
        self,
        state: AgentState,
        event_type: str,
        summary: str,
        relevant_ids: Optional[Dict[str, str]] = None,
        details: Optional[Dict[str, Any]] = None,
        step_number: Optional[int] = None,
        actor: str = "agent",
        tool: Optional[str] = None,
        arguments: Optional[Dict[str, Any]] = None,
        result: Optional[Dict[str, Any]] = None,
        reason: Optional[str] = None,
        confidence: Optional[float] = None,
        evidence_refs: Optional[List[str]] = None,
    ) -> AuditEvent:
        event = state.record_event(
            event_type=event_type,
            summary=summary,
            relevant_ids=relevant_ids or {},
            details=details or {},
            step_number=step_number,
            actor=actor,
            tool=tool,
            arguments=arguments,
            result=result,
            reason=reason,
            confidence=confidence,
            evidence_refs=evidence_refs or [],
        )
        if self.event_callback:
            self.event_callback(event)
        return event

    def run(
        self,
        goal: str,
        role_id: Optional[str] = None,
        max_steps: int = 25,
    ) -> AgentState:
        """Executes the closed-loop autonomous IAM remediation workflow."""
        # Initialize budget tracking
        budget_tracker = BudgetTracker(self.budget)

        # Initialize explicit remediation plan
        plan = AgentPlan(
            objective=goal,
            assumptions=["Unobserved permissions may include hidden transitive dependencies"],
            required_evidence=["access_logs", "simulation_verification", "dependency_graph"],
            verification_requirements=["workflows_passed", "protected_resources_isolated", "structural_integrity"],
            risk_level="medium",
            status="active",
        )

        state = AgentState(
            goal=goal,
            current_role=role_id,
            current_phase="OBSERVING",
            current_plan=plan,
        )

        planned_policy_version = "v1"

        self._emit_event(
            state=state,
            event_type="goal_received",
            summary=f"Received security goal: '{goal}'",
            relevant_ids={"role_id": role_id or "unspecified"},
            details={"goal": goal, "plan": plan.model_dump()},
            step_number=0,
            actor="user",
            reason="Goal received from caller",
        )

        step_count = 0
        while state.current_phase not in ["COMPLETED", "FAILED"] and step_count < max_steps:
            step_count += 1

            # Bounded Loop Guard: check budget limits
            budget_exhausted_reason = budget_tracker.check_exhausted()
            if budget_exhausted_reason:
                state.current_phase = "FAILED"
                state.stop_reason = "budget_exhausted"
                state.final_outcome = {
                    "status": "budget_exhausted",
                    "message": f"Execution halted safely: {budget_exhausted_reason}",
                    "telemetry": budget_tracker.telemetry(),
                }
                self._emit_event(
                    state=state,
                    event_type="final_outcome",
                    summary=f"Remediation halted safely: {budget_exhausted_reason}",
                    relevant_ids={"role_id": state.current_role or ""},
                    details=state.final_outcome,
                    step_number=step_count,
                    actor="controller",
                    reason="Resource limit reached",
                )
                break

            budget_tracker.record_iteration()

            # Dynamic Reasoner decides next action
            available_tools = self.tools.list_tools()
            decision = self.reasoner.decide(
                state=state,
                goal=goal,
                available_tools=available_tools,
                evidence=state.observed_evidence,
                history=state.tool_calls[-10:],
            )

            # Record decision history
            state.decision_history.append(decision.model_dump())

            # Emit decide audit event
            self._emit_event(
                state=state,
                event_type="decide",
                summary=f"Decision: {decision.decision_type} ({decision.reason})",
                relevant_ids={"role_id": state.current_role or "", "tool": decision.tool_name or ""},
                details=decision.model_dump(),
                step_number=step_count,
                actor="agent",
                reason=decision.reason,
                confidence=decision.confidence,
            )

            # Handle Decision Types
            if decision.decision_type == "complete":
                verification = state.verification_result or {}
                if verification.get("passed", False):
                    state.current_phase = "COMPLETED"
                    state.stop_reason = "verified_success"
                    plan.mark_verified()
                    state.final_outcome = {
                        "status": "success",
                        "message": decision.reason or decision.thought,
                        "details": decision.metadata,
                    }
                    self._emit_event(
                        state=state,
                        event_type="final_outcome",
                        summary="Remediation cycle completed successfully.",
                        relevant_ids={"role_id": state.current_role or ""},
                        details=state.final_outcome,
                        step_number=step_count,
                        actor="agent",
                        reason=decision.reason,
                        confidence=decision.confidence,
                    )
                else:
                    state.current_phase = "FAILED"
                    state.stop_reason = "unrecoverable_failure"
                    plan.mark_failed("Verification checks failed")
                    state.final_outcome = {
                        "status": "verification_failed",
                        "message": f"Verification checks did not pass: {verification.get('details')}",
                    }
                    self._emit_event(
                        state=state,
                        event_type="final_outcome",
                        summary=f"Remediation halted with verification failure: {verification.get('details')}",
                        relevant_ids={"role_id": state.current_role or ""},
                        details=state.final_outcome,
                        step_number=step_count,
                        actor="agent",
                    )
                break

            elif decision.decision_type == "escalate":
                state.current_phase = "FAILED"
                state.stop_reason = "human_approval_required"
                state.final_outcome = {
                    "status": "escalated",
                    "message": decision.reason,
                    "details": decision.metadata,
                }
                self._emit_event(
                    state=state,
                    event_type="escalate",
                    summary=f"Remediation escalated for human approval: {decision.reason}",
                    relevant_ids={"role_id": state.current_role or ""},
                    details=state.final_outcome,
                    step_number=step_count,
                    actor="agent",
                    reason=decision.reason,
                    confidence=decision.confidence,
                )
                break

            elif decision.decision_type == "abort":
                state.current_phase = "FAILED"
                state.stop_reason = "unrecoverable_failure"
                plan.mark_failed(decision.reason)
                state.final_outcome = {
                    "status": "failed",
                    "message": decision.reason or decision.thought,
                    "details": decision.metadata,
                }
                self._emit_event(
                    state=state,
                    event_type="final_outcome",
                    summary=f"Remediation cycle halted with failure: {decision.reason or decision.thought}",
                    relevant_ids={"role_id": state.current_role or ""},
                    details=state.final_outcome,
                    step_number=step_count,
                    actor="agent",
                    reason=decision.reason,
                )
                break

            elif decision.decision_type == "replan":
                budget_tracker.record_replan()
                plan.revise(replan_reason=decision.reason)
                state.current_phase = "REPLANNING"
                continue

            elif decision.decision_type == "tool_call":
                tool_name = decision.tool_name
                tool_args = decision.arguments or decision.tool_args or {}

                if not tool_name:
                    raise ValueError("Decision with decision_type='tool_call' must specify tool_name.")

                budget_tracker.record_tool_call()

                # Normalize aliases
                canonical_tool_name = tool_name
                if tool_name == "inspect_role":
                    canonical_tool_name = "get_role"
                elif tool_name == "simulate_policy_change":
                    canonical_tool_name = "simulate_policy"
                elif tool_name == "rollback_policy_change":
                    canonical_tool_name = "rollback_policy"
                elif tool_name == "inspect_principal":
                    canonical_tool_name = "get_principal"

                # Lifecycle event tagging
                meta_phase = decision.metadata.get("candidate_phase")
                if meta_phase == "initial_proposal":
                    state.current_phase = "PROPOSING"
                    candidate_change = {
                        "role_id": state.current_role,
                        "remove_permissions": decision.metadata.get("remove_permissions", []),
                        "proposed_permissions": decision.metadata.get("proposed_permissions", []),
                        "reason": decision.reason or decision.thought,
                    }
                    state.candidate_policy_changes.append(candidate_change)
                    plan.candidate_changes = [candidate_change]
                    self._emit_event(
                        state=state,
                        event_type="policy_candidate_generated",
                        summary=f"Generated initial candidate policy removing: {candidate_change['remove_permissions']}",
                        relevant_ids={"role_id": state.current_role or ""},
                        details=candidate_change,
                        step_number=step_count,
                        actor="agent",
                    )
                elif meta_phase == "replan_proposal":
                    budget_tracker.record_replan()
                    state.current_phase = "REPLANNING"
                    replan_change = {
                        "role_id": state.current_role,
                        "retained_dependencies": decision.metadata.get("retained_dependencies", []),
                        "remove_permissions": decision.metadata.get("remove_permissions", []),
                        "proposed_permissions": decision.metadata.get("proposed_permissions", []),
                        "reason": decision.reason or decision.thought,
                    }
                    state.replans.append(replan_change)
                    plan.revise(
                        replan_reason=replan_change["reason"],
                        new_candidate_changes=[replan_change],
                    )
                    self._emit_event(
                        state=state,
                        event_type="replan_started",
                        summary=(
                            f"Replanning policy: retaining {replan_change['retained_dependencies']} "
                            f"and removing {replan_change['remove_permissions']}"
                        ),
                        relevant_ids={"role_id": state.current_role or ""},
                        details=replan_change,
                        step_number=step_count,
                        actor="agent",
                    )

                if canonical_tool_name == "simulate_policy":
                    state.current_phase = "SIMULATING"
                    self._emit_event(
                        state=state,
                        event_type="simulation_started",
                        summary=f"Simulating policy permissions on {state.current_role}",
                        relevant_ids={"role_id": state.current_role or ""},
                        details=tool_args,
                        step_number=step_count,
                        actor="agent",
                    )
                elif canonical_tool_name == "verify_required_access":
                    state.current_phase = "VERIFYING"
                    self._emit_event(
                        state=state,
                        event_type="verification_started",
                        summary=f"Starting deterministic verification on {state.current_role}",
                        relevant_ids={"role_id": state.current_role or ""},
                        details=tool_args,
                        step_number=step_count,
                        actor="agent",
                    )

                # Record tool invocation in state & audit log
                tool_call_record = {"step": step_count, "tool_name": tool_name, "args": tool_args}
                state.tool_calls.append(tool_call_record)
                self._emit_event(
                    state=state,
                    event_type="tool_called",
                    summary=f"Executing tool '{tool_name}' with args {tool_args}",
                    relevant_ids={"role_id": state.current_role or "", "tool": tool_name},
                    details=tool_args,
                    step_number=step_count,
                    actor="agent",
                    tool=tool_name,
                    arguments=tool_args,
                    reason=decision.reason,
                    confidence=decision.confidence,
                )

                # DETERMINISTIC SECURITY KERNEL GATE:
                # Intercept any mutation tool (apply_policy_change) before execution
                if canonical_tool_name == "apply_policy_change" and self.security_kernel:
                    last_sim = state.simulation_results[-1] if state.simulation_results else None
                    role_info = state.observed_evidence.get("role", {})
                    current_role_active = role_info.get("active_permissions", [])

                    # Compute proposed permissions
                    if "new_permissions" in tool_args and tool_args["new_permissions"] is not None:
                        proposed = tool_args["new_permissions"]
                    elif "keep_permissions" in tool_args and tool_args["keep_permissions"] is not None:
                        proposed = tool_args["keep_permissions"]
                    elif "remove_permissions" in tool_args and tool_args["remove_permissions"] is not None:
                        proposed = [p for p in current_role_active if p not in tool_args["remove_permissions"]]
                    else:
                        proposed = current_role_active

                    gate_result = self.security_kernel.evaluate_proposal(
                        role_id=state.current_role or "PaymentServiceRole",
                        proposed_permissions=proposed,
                        planned_policy_version=planned_policy_version,
                        confidence=decision.confidence,
                        simulation_result=last_sim,
                        risk_level=plan.risk_level,
                    )

                    if gate_result.decision == "deny":
                        # Deny execution: Security Kernel vetoes mutation
                        self._emit_event(
                            state=state,
                            event_type="security_gate_denied",
                            summary=f"Security Kernel DENIED policy mutation: {gate_result.reason_codes}",
                            relevant_ids={"role_id": state.current_role or ""},
                            details=gate_result.model_dump(),
                            step_number=step_count,
                            actor="security_kernel",
                            reason=f"Authoritative denial: {gate_result.reason_codes}",
                        )
                        # If stale state was the issue, refresh state and replan
                        if "stale_state_detected" in gate_result.reason_codes:
                            state.current_phase = "REPLANNING"
                            # Refresh role info
                            role_res = self.tools.execute("get_role", {"role_id": state.current_role})
                            if role_res.success:
                                state.observed_evidence["role"] = role_res.data
                                planned_policy_version = role_res.data.get("current_version", "v1")
                        continue

                    elif gate_result.decision == "escalate":
                        state.current_phase = "FAILED"
                        state.stop_reason = "human_approval_required"
                        state.final_outcome = {
                            "status": "escalated",
                            "message": f"Security Kernel requires human approval: {gate_result.reason_codes}",
                            "details": gate_result.model_dump(),
                        }
                        self._emit_event(
                            state=state,
                            event_type="escalate",
                            summary=f"Security Kernel escalated for human approval: {gate_result.reason_codes}",
                            relevant_ids={"role_id": state.current_role or ""},
                            details=state.final_outcome,
                            step_number=step_count,
                            actor="security_kernel",
                        )
                        break

                # Safe dispatch through tool registry (agent never executes arbitrary shell or Python code)
                result = self.tools.execute(canonical_tool_name, tool_args)

                tool_result_record = {
                    "step": step_count,
                    "tool_name": tool_name,
                    "success": result.success,
                    "data": result.data,
                    "error": result.error,
                    "metadata": result.metadata,
                }
                state.tool_results.append(tool_result_record)
                self._emit_event(
                    state=state,
                    event_type="tool_result",
                    summary=f"Tool '{tool_name}' returned success={result.success}",
                    relevant_ids={"role_id": state.current_role or "", "tool": tool_name},
                    details={"data": result.data, "error": result.error},
                    step_number=step_count,
                    actor="tool",
                    tool=tool_name,
                    result={"success": result.success, "error": result.error},
                )

                # Update structured state evidence based on tool output
                if result.success:
                    if canonical_tool_name == "get_role":
                        state.observed_evidence["role"] = result.data
                        if not state.current_role and result.data:
                            state.current_role = result.data.get("id")
                        planned_policy_version = result.data.get("current_version", "v1")
                    elif canonical_tool_name == "get_access_history":
                        state.observed_evidence["access_logs"] = result.data
                    elif canonical_tool_name == "find_unused_permissions":
                        state.observed_evidence["unused_permissions"] = result.data
                        state.current_phase = "ANALYZING"
                    elif canonical_tool_name == "get_service_dependencies":
                        state.observed_evidence["dependencies"] = result.data
                        deps = result.data or []
                        dep_summary = ", ".join(
                            f"{d['service']}->{d['calls_service']}->{d['downstream_dependency']}"
                            for d in deps
                        )
                        self._emit_event(
                            state=state,
                            event_type="dependency_discovered",
                            summary=f"Discovered transitive service dependency: {dep_summary}",
                            relevant_ids={"role_id": state.current_role or ""},
                            details={"dependencies": deps},
                            step_number=step_count,
                            actor="agent",
                            evidence_refs=[d.get("required_permission", "") for d in deps],
                        )
                    elif canonical_tool_name == "simulate_policy":
                        sim_data = result.data or {}
                        state.simulation_results.append(sim_data)
                        if not sim_data.get("success", True):
                            state.failures.append(sim_data)
                            self._emit_event(
                                state=state,
                                event_type="simulation_failed",
                                summary=(
                                    f"Simulation failed on workflow '{sim_data.get('failed_workflow')}': "
                                    f"missing permission '{sim_data.get('missing_permission')}'"
                                ),
                                relevant_ids={
                                    "role_id": state.current_role or "",
                                    "workflow": sim_data.get("failed_workflow") or "",
                                },
                                details=sim_data,
                                step_number=step_count,
                                actor="simulator",
                                evidence_refs=[sim_data.get("evidence_id", "")],
                            )
                    elif canonical_tool_name == "apply_policy_change":
                        state.current_phase = "APPLYING"
                        applied_data = result.data or {}
                        new_version_id = applied_data.get("version_id")
                        self._emit_event(
                            state=state,
                            event_type="policy_applied",
                            summary=f"Applied policy version {new_version_id} to {state.current_role}",
                            relevant_ids={
                                "role_id": state.current_role or "",
                                "version_id": new_version_id or "",
                            },
                            details=applied_data,
                            step_number=step_count,
                            actor="agent",
                        )

                        # Compute and store policy diff
                        role_info = state.observed_evidence.get("role", {})
                        orig_perms = role_info.get("active_permissions", [])
                        new_perms = applied_data.get("permissions", [])
                        last_replan = state.replans[-1] if state.replans else {}
                        retained = last_replan.get("retained_dependencies", ["kms:Decrypt"])

                        diff = compute_policy_diff(
                            role_id=state.current_role or "PaymentServiceRole",
                            from_version=planned_policy_version,
                            to_version=new_version_id,
                            original_permissions=orig_perms,
                            new_permissions=new_perms,
                            retained_dependencies=retained,
                            simulation_result=state.simulation_results[-1] if state.simulation_results else None,
                        )
                        state.policy_diff = diff.model_dump()

                    elif canonical_tool_name == "verify_required_access":
                        verify_data = result.data or {}
                        state.verification_result = verify_data
                        if verify_data.get("passed", False):
                            self._emit_event(
                                state=state,
                                event_type="verification_passed",
                                summary="Deterministic verification passed: all invariants satisfied.",
                                relevant_ids={"role_id": state.current_role or ""},
                                details=verify_data,
                                step_number=step_count,
                                actor="verifier",
                            )
                        else:
                            self._emit_event(
                                state=state,
                                event_type="verification_failed",
                                summary=f"Deterministic verification failed: {verify_data.get('details')}",
                                relevant_ids={"role_id": state.current_role or ""},
                                details=verify_data,
                                step_number=step_count,
                                actor="verifier",
                            )
                            # Rollback automated recovery if verification fails
                            if self.capabilities.supports_rollback and "apply_policy_change" in [c["tool_name"] for c in state.tool_calls]:
                                rb_result = self.tools.execute("rollback_policy", {"role_id": state.current_role, "target_version": planned_policy_version})
                                self._emit_event(
                                    state=state,
                                    event_type="rollback",
                                    summary=f"Automated rollback invoked for {state.current_role} to {planned_policy_version}",
                                    relevant_ids={"role_id": state.current_role or ""},
                                    details=rb_result.data or {},
                                    step_number=step_count,
                                    actor="security_kernel",
                                )
                    elif canonical_tool_name == "rollback_policy":
                        self._emit_event(
                            state=state,
                            event_type="rollback",
                            summary=f"Rolled back {state.current_role} to version {result.data.get('version_id')}",
                            relevant_ids={"role_id": state.current_role or ""},
                            details=result.data,
                            step_number=step_count,
                            actor="agent",
                        )

        if step_count >= max_steps and state.current_phase not in ["COMPLETED", "FAILED"]:
            state.current_phase = "FAILED"
            state.stop_reason = "budget_exhausted"
            state.final_outcome = {
                "status": "failed",
                "message": f"Agent reached maximum execution steps ({max_steps}) without resolution.",
            }

        # Telemetry recording
        state.telemetry = budget_tracker.telemetry()

        # Persist final state
        self.state_store.save(state)
        return state

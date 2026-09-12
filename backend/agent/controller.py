"""Autonomous Agent Controller orchestrating the observe-reason-simulate-replan-verify loop."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from backend.agent.reasoner import Reasoner
from backend.state.models import AgentState, AuditEvent
from backend.state.store import InMemoryStateStore, StateStore
from backend.tools.registry import ToolRegistry


class AgentController:
    """Core controller coordinating reasoner decisions, tool execution, state, and audit logs."""

    def __init__(
        self,
        reasoner: Reasoner,
        tool_registry: ToolRegistry,
        state_store: Optional[StateStore] = None,
        event_callback: Optional[Callable[[AuditEvent], None]] = None,
    ) -> None:
        self.reasoner = reasoner
        self.tools = tool_registry
        self.state_store = state_store or InMemoryStateStore()
        self.event_callback = event_callback

    def _emit_event(
        self,
        state: AgentState,
        event_type: str,
        summary: str,
        relevant_ids: Optional[Dict[str, str]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        event = state.record_event(
            event_type=event_type,
            summary=summary,
            relevant_ids=relevant_ids or {},
            details=details or {},
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
        state = AgentState(
            goal=goal,
            current_role=role_id,
            current_phase="OBSERVING",
        )

        self._emit_event(
            state=state,
            event_type="goal_received",
            summary=f"Received security goal: '{goal}'",
            relevant_ids={"role_id": role_id or "unspecified"},
            details={"goal": goal},
        )

        step_count = 0
        while state.current_phase not in ["COMPLETED", "FAILED"] and step_count < max_steps:
            step_count += 1
            decision = self.reasoner.decide(state)

            if decision.action_type == "complete":
                state.current_phase = "COMPLETED"
                state.final_outcome = {
                    "status": "success",
                    "message": decision.thought,
                    "details": decision.metadata,
                }
                self._emit_event(
                    state=state,
                    event_type="final_outcome",
                    summary="Remediation cycle completed successfully.",
                    relevant_ids={"role_id": state.current_role or ""},
                    details=state.final_outcome,
                )
                break

            elif decision.action_type == "fail":
                state.current_phase = "FAILED"
                state.final_outcome = {
                    "status": "failed",
                    "message": decision.thought,
                    "details": decision.metadata,
                }
                self._emit_event(
                    state=state,
                    event_type="final_outcome",
                    summary=f"Remediation cycle halted with failure: {decision.thought}",
                    relevant_ids={"role_id": state.current_role or ""},
                    details=state.final_outcome,
                )
                break

            elif decision.action_type == "call_tool":
                tool_name = decision.tool_name
                tool_args = decision.tool_args or {}

                if not tool_name:
                    raise ValueError("Decision with action_type='call_tool' must specify tool_name.")

                # Inspect decision metadata for lifecycle event tagging
                meta_phase = decision.metadata.get("candidate_phase")
                if meta_phase == "initial_proposal":
                    state.current_phase = "PROPOSING"
                    candidate_change = {
                        "role_id": state.current_role,
                        "remove_permissions": decision.metadata.get("remove_permissions", []),
                        "proposed_permissions": decision.metadata.get("proposed_permissions", []),
                        "reason": decision.thought,
                    }
                    state.candidate_policy_changes.append(candidate_change)
                    self._emit_event(
                        state=state,
                        event_type="policy_candidate_generated",
                        summary=f"Generated initial candidate policy removing: {candidate_change['remove_permissions']}",
                        relevant_ids={"role_id": state.current_role or ""},
                        details=candidate_change,
                    )
                elif meta_phase == "replan_proposal":
                    state.current_phase = "REPLANNING"
                    replan_change = {
                        "role_id": state.current_role,
                        "retained_dependencies": decision.metadata.get("retained_dependencies", []),
                        "remove_permissions": decision.metadata.get("remove_permissions", []),
                        "proposed_permissions": decision.metadata.get("proposed_permissions", []),
                        "reason": decision.thought,
                    }
                    state.replans.append(replan_change)
                    self._emit_event(
                        state=state,
                        event_type="replan_started",
                        summary=(
                            f"Replanning policy: retaining {replan_change['retained_dependencies']} "
                            f"and removing {replan_change['remove_permissions']}"
                        ),
                        relevant_ids={"role_id": state.current_role or ""},
                        details=replan_change,
                    )

                if tool_name == "simulate_policy":
                    state.current_phase = "SIMULATING"
                    self._emit_event(
                        state=state,
                        event_type="simulation_started",
                        summary=f"Simulating policy permissions on {state.current_role}",
                        relevant_ids={"role_id": state.current_role or ""},
                        details=tool_args,
                    )
                elif tool_name == "verify_required_access":
                    state.current_phase = "VERIFYING"
                    self._emit_event(
                        state=state,
                        event_type="verification_started",
                        summary=f"Starting deterministic verification on {state.current_role}",
                        relevant_ids={"role_id": state.current_role or ""},
                        details=tool_args,
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
                )

                # Safe dispatch through tool registry (agent never calls arbitrary Python functions)
                result = self.tools.execute(tool_name, tool_args)

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
                )

                # Update structured state evidence based on tool output
                if result.success:
                    if tool_name == "get_role":
                        state.observed_evidence["role"] = result.data
                    elif tool_name == "get_access_history":
                        state.observed_evidence["access_logs"] = result.data
                    elif tool_name == "find_unused_permissions":
                        state.observed_evidence["unused_permissions"] = result.data
                        state.current_phase = "ANALYZING"
                    elif tool_name == "get_service_dependencies":
                        state.observed_evidence["dependencies"] = result.data
                        deps = result.data
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
                        )
                    elif tool_name == "simulate_policy":
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
                            )
                    elif tool_name == "apply_policy_change":
                        state.current_phase = "APPLYING"
                        self._emit_event(
                            state=state,
                            event_type="policy_applied",
                            summary=f"Applied policy version {result.data.get('version_id')} to {state.current_role}",
                            relevant_ids={
                                "role_id": state.current_role or "",
                                "version_id": result.data.get("version_id", ""),
                            },
                            details=result.data,
                        )
                    elif tool_name == "verify_required_access":
                        verify_data = result.data or {}
                        state.verification_result = verify_data
                        if verify_data.get("passed", False):
                            self._emit_event(
                                state=state,
                                event_type="verification_passed",
                                summary="Deterministic verification passed: all invariants satisfied.",
                                relevant_ids={"role_id": state.current_role or ""},
                                details=verify_data,
                            )
                        else:
                            self._emit_event(
                                state=state,
                                event_type="verification_failed",
                                summary=f"Deterministic verification failed: {verify_data.get('details')}",
                                relevant_ids={"role_id": state.current_role or ""},
                                details=verify_data,
                            )
                    elif tool_name == "rollback_policy":
                        self._emit_event(
                            state=state,
                            event_type="rollback",
                            summary=f"Rolled back {state.current_role} to version {result.data.get('version_id')}",
                            relevant_ids={"role_id": state.current_role or ""},
                            details=result.data,
                        )

        if step_count >= max_steps and state.current_phase not in ["COMPLETED", "FAILED"]:
            state.current_phase = "FAILED"
            state.final_outcome = {
                "status": "failed",
                "message": f"Agent reached maximum execution steps ({max_steps}) without resolution.",
            }

        # Persist final state
        self.state_store.save(state)
        return state

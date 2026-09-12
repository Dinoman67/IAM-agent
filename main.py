"""CLI entry point for PS10 Autonomous Cloud IAM Least-Privilege Mitigator (Phase 2)."""

from __future__ import annotations

import argparse
import os
import sys
from typing import Optional

from backend.agent.controller import AgentController
from backend.agent.reasoner import DeterministicReasoner, LLMReasoner
from backend.environment.loader import load_environment
from backend.security.diff import PolicyDiff
from backend.state.models import AuditEvent
from backend.tools.iam_tools import create_extended_tool_registry

step_counter = 0


def format_cli_output(event: AuditEvent) -> None:
    """Format audit events into the required hackathon demo progression style."""
    global step_counter
    etype = event.event_type
    details = event.details

    if etype == "goal_received":
        print("=" * 70)
        print("PS10 IAM AGENT — Autonomous Least-Privilege Mitigator")
        print("=" * 70)
        print(f"\nGoal:\n{event.summary.replace('Received security goal: ', '').strip('\'')}\n")

    elif etype == "tool_result" and event.relevant_ids.get("tool") in ["get_role", "inspect_role"]:
        step_counter += 1
        role_data = details.get("data", {})
        perms = role_data.get("active_permissions", [])
        print(f"[{step_counter:02d}] OBSERVE\nInspecting role '{role_data.get('id')}' (found {len(perms)} active permissions):\n" + "\n".join(f"  - {p}" for p in perms) + "\n")

    elif etype == "policy_candidate_generated":
        step_counter += 1
        remove = details.get("remove_permissions", [])
        print(f"[{step_counter:02d}] DECIDE\nCandidate excessive permissions identified. Proposing removal of:\n" + "\n".join(f"  - {p}" for p in remove) + "\n")

    elif etype == "simulation_started":
        step_counter += 1
        print(f"[{step_counter:02d}] ACT\nSimulating policy change against business workflows...")

    elif etype == "simulation_failed":
        step_counter += 1
        wf = details.get("failed_workflow")
        missing = details.get("missing_permission")
        print(f"[{step_counter:02d}] ADAPT\nSimulation failed: workflow '{wf}' requires '{missing}'\n")

    elif etype == "tool_called" and details.get("service") == "PaymentService":
        step_counter += 1
        print(f"[{step_counter:02d}] DECIDE\nInvestigating dependencies and transitive cryptographic couplings...")

    elif etype == "dependency_discovered":
        step_counter += 1
        deps = details.get("dependencies", [])
        for d in deps:
            print(f"[{step_counter:02d}] ACT\n{d.get('service')} → {d.get('calls_service')} → {d.get('downstream_dependency')} discovered (requires {d.get('required_permission')})\nReason: {d.get('reason')}\n")

    elif etype == "replan_started":
        step_counter += 1
        retained = details.get("retained_dependencies", [])
        remove = details.get("remove_permissions", [])
        print(f"[{step_counter:02d}] ADAPT\nReplanning remediation: retaining critical dependency {retained}.\nRevised removal list:\n" + "\n".join(f"  - {p}" for p in remove) + "\n")

    elif etype == "tool_result" and event.relevant_ids.get("tool") in ["simulate_policy", "simulate_policy_change"]:
        sim_data = details.get("data", {})
        if sim_data.get("success"):
            step_counter += 1
            print(f"[{step_counter:02d}] ACT\nRe-simulating revised policy...\nSimulation PASSED (all workflows and dependencies satisfied).\n")

    elif etype == "policy_applied":
        step_counter += 1
        ver_id = details.get("version_id")
        role_id = event.relevant_ids.get("role_id")
        print(f"[{step_counter:02d}] ACT\nApplying policy version {ver_id} to {role_id} under Security Kernel authorization.\n")

    elif etype == "verification_passed":
        step_counter += 1
        v_data = details
        print(f"[{step_counter:02d}] VERIFY")
        for detail in v_data.get("details", []):
            print(f"  {detail}")
        print()

    elif etype == "final_outcome":
        step_counter += 1
        status = details.get("status")
        if status == "success":
            print(f"[{step_counter:02d}] COMPLETE\nLeast-privilege remediation verified successfully.\n")
        else:
            print(f"[{step_counter:02d}] COMPLETE\nExecution finished with status: {status}\n")


def run_demo(
    scenario: Optional[str] = None,
    role_id: str = "PaymentServiceRole",
    use_mock: bool = False,
) -> int:
    """Runs the autonomous IAM least-privilege mitigation demo."""
    global step_counter
    step_counter = 0

    env = load_environment()
    tool_registry = create_extended_tool_registry(env)

    if use_mock or os.getenv("MOCK_LLM", "false").lower() in ("true", "1", "yes"):
        reasoner = DeterministicReasoner(target_role_id=role_id)
    else:
        reasoner = LLMReasoner(mock_fallback=True)

    controller = AgentController(
        reasoner=reasoner,
        tool_registry=tool_registry,
        event_callback=format_cli_output,
        environment=env,
    )

    goal = f"Make {role_id} least privilege without breaking required workflows."
    state = controller.run(goal=goal, role_id=role_id)

    # Observability report
    print("-" * 70)
    print("TELEMETRY & BUDGET USAGE:")
    telem = state.telemetry
    print(f"  iterations:  {telem.get('iterations', 'N/A')}")
    print(f"  tool calls:  {telem.get('tool_calls', 'N/A')}")
    print(f"  replans:     {telem.get('replans', 'N/A')}")
    print(f"  runtime:     {telem.get('runtime_ms', 0)}ms")

    if state.policy_diff:
        print("\nPOLICY DIFF:")
        diff = PolicyDiff.model_validate(state.policy_diff)
        print(diff.render_markdown())

    print("-" * 70)

    return 0 if state.current_phase == "COMPLETED" else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PS10 Autonomous Cloud IAM Least-Privilege Mitigator (Phase 2 CLI)"
    )
    parser.add_argument(
        "--scenario",
        type=str,
        default="payment",
        help="Scenario to execute (default: payment)",
    )
    parser.add_argument(
        "--role",
        type=str,
        default="PaymentServiceRole",
        help="Target IAM role ID (default: PaymentServiceRole)",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Run with deterministic mock reasoner (no API key required)",
    )

    args = parser.parse_args()
    exit_code = run_demo(scenario=args.scenario, role_id=args.role, use_mock=args.mock)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

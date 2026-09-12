"""CLI entry point for Phase 1 Autonomous Cloud IAM Least-Privilege Mitigator."""

from __future__ import annotations

import argparse
import sys
from typing import Optional

from backend.agent.controller import AgentController
from backend.agent.reasoner import DeterministicReasoner
from backend.environment.loader import load_environment
from backend.state.models import AuditEvent
from backend.tools.iam_tools import create_default_tool_registry


def format_cli_output(event: AuditEvent) -> None:
    """Format audit events into the required hackathon demo progression style."""
    etype = event.event_type
    details = event.details

    if etype == "goal_received":
        print(f"\n[GOAL]\n{event.summary.replace('Received security goal: ', '').strip('\'')}\n")

    elif etype == "tool_result" and event.relevant_ids.get("tool") == "get_role":
        role_data = details.get("data", {})
        perms = role_data.get("active_permissions", [])
        print(f"[OBSERVE]\nFound {len(perms)} active permissions on {role_data.get('id')}:\n" + "\n".join(f"  - {p}" for p in perms) + "\n")

    elif etype == "tool_result" and event.relevant_ids.get("tool") == "find_unused_permissions":
        unused = details.get("data", [])
        print(f"[ANALYZE]\n{len(unused)} permissions appear unlogged / candidate excessive:\n" + "\n".join(f"  - {p}" for p in unused) + "\n")

    elif etype == "policy_candidate_generated":
        remove = details.get("remove_permissions", [])
        print(f"[PROPOSE]\nCandidate least-privilege policy. Propose removing:\n" + "\n".join(f"  - {p}" for p in remove) + "\n")

    elif etype == "simulation_failed":
        wf = details.get("failed_workflow")
        missing = details.get("missing_permission")
        print(f"[SIMULATE]\nFAILED\nReason: workflow '{wf}' requires '{missing}'\n")

    elif etype == "tool_called" and details.get("service") == "PaymentService":
        print("[ADAPT]\nInvestigating service dependencies and transitive architecture...\n")

    elif etype == "dependency_discovered":
        deps = details.get("dependencies", [])
        for d in deps:
            print(f"[DISCOVER]\n{d.get('service')} → {d.get('calls_service')} → {d.get('downstream_dependency')} (requires {d.get('required_permission')})\nReason: {d.get('reason')}\n")

    elif etype == "replan_started":
        retained = details.get("retained_dependencies", [])
        remove = details.get("remove_permissions", [])
        print(f"[REPLAN]\nRetaining critical dependency: {', '.join(retained)}\nRevised removal list:\n" + "\n".join(f"  - {p}" for p in remove) + "\n")

    elif etype == "tool_result" and event.relevant_ids.get("tool") == "simulate_policy":
        sim_data = details.get("data", {})
        if sim_data.get("success"):
            print("[SIMULATE]\nPASSED\nAll workflows and transitive dependencies satisfied.\n")

    elif etype == "policy_applied":
        ver_id = details.get("version_id")
        role_id = event.relevant_ids.get("role_id")
        print(f"[APPLY]\nPolicy version {ver_id} created and activated for {role_id}\n")

    elif etype == "verification_passed":
        v_data = details
        checks = v_data.get("checks", {})
        print("[VERIFY]")
        for detail in v_data.get("details", []):
            print(f"  {detail}")
        print()

    elif etype == "final_outcome":
        status = details.get("status")
        if status == "success":
            print(f"[FINAL]\nLeast-privilege policy verified successfully.\n")
        else:
            print(f"[FINAL]\nExecution finished with status: {status}\n")


def run_demo(scenario: Optional[str] = None, role_id: str = "PaymentServiceRole") -> int:
    """Runs the deterministic Phase 1 IAM mitigation scenario."""
    env = load_environment()
    tool_registry = create_default_tool_registry(env)
    reasoner = DeterministicReasoner(target_role_id=role_id)
    controller = AgentController(
        reasoner=reasoner,
        tool_registry=tool_registry,
        event_callback=format_cli_output,
    )

    goal = f"Reduce excessive permissions for {role_id} without breaking required services."
    state = controller.run(goal=goal, role_id=role_id)

    return 0 if state.current_phase == "COMPLETED" else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Autonomous Cloud IAM Least-Privilege Mitigator (Phase 1 CLI)"
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

    args = parser.parse_args()
    exit_code = run_demo(scenario=args.scenario, role_id=args.role)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

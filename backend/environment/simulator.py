"""Deterministic Policy Simulator for impact analysis before policy mutation."""

from __future__ import annotations

import fnmatch
import uuid
from typing import List, Optional

from backend.environment.loader import IAMEnvironment
from backend.models.schemas import SimulationResult


class PolicySimulator:
    """Simulates IAM authorization changes against required workflows and dependencies."""

    def __init__(self, environment: IAMEnvironment) -> None:
        self.env = environment

    @staticmethod
    def is_action_allowed(action: str, permissions: List[str]) -> bool:
        """Determines if a requested action is permitted under a set of permissions.
        Supports standard IAM wildcards, e.g. 'ec2:*' or '*' or exact 's3:GetObject'.
        """
        action_lower = action.lower()
        for perm in permissions:
            perm_lower = perm.lower()
            if perm_lower == "*" or perm_lower == action_lower:
                return True
            # Check wildcard prefix matching, e.g. 's3:*' matches 's3:GetObject'
            if fnmatch.fnmatch(action_lower, perm_lower):
                return True
        return False

    def simulate(
        self, role_id: str, proposed_permissions: List[str]
    ) -> SimulationResult:
        """Evaluates whether all critical workflows for role_id succeed under proposed_permissions.
        Identifies exact missing permissions, failing workflows, and downstream dependencies.
        """
        role = self.env.get_role(role_id)
        if not role:
            return SimulationResult(
                success=False,
                evidence_id=f"sim-{uuid.uuid4().hex[:6]}",
                details=f"Role '{role_id}' does not exist.",
            )

        # Get relevant workflows for role
        role_workflows = [w for w in self.env.data.workflows if w.role_id == role_id]

        for workflow in role_workflows:
            for required_perm in workflow.required_permissions:
                if not self.is_action_allowed(required_perm, proposed_permissions):
                    # Missing required permission detected!
                    # Check if this missing permission corresponds to a known downstream dependency
                    broken_dep = None
                    for dep in self.env.data.dependencies:
                        if dep.required_permission.lower() == required_perm.lower():
                            broken_dep = f"{dep.service} -> {dep.calls_service} -> {dep.downstream_dependency}"
                            break

                    evidence_id = f"sim-{uuid.uuid4().hex[:6]}"
                    details = (
                        f"Workflow '{workflow.id}' failed during simulation: "
                        f"Action '{required_perm}' is not permitted under proposed policy."
                    )
                    if broken_dep:
                        details += f" (Transitive dependency broken: {broken_dep})"

                    sim_run = {
                        "evidence_id": evidence_id,
                        "role_id": role_id,
                        "proposed_permissions": proposed_permissions,
                        "success": False,
                        "failed_workflow": workflow.id,
                        "missing_permission": required_perm,
                        "broken_dependency": broken_dep,
                    }
                    self.env.data.simulation_runs.append(sim_run)

                    return SimulationResult(
                        success=False,
                        failed_workflow=workflow.id,
                        missing_permission=required_perm,
                        broken_dependency=broken_dep,
                        evidence_id=evidence_id,
                        details=details,
                    )

        evidence_id = f"sim-{uuid.uuid4().hex[:6]}"
        sim_run = {
            "evidence_id": evidence_id,
            "role_id": role_id,
            "proposed_permissions": proposed_permissions,
            "success": True,
            "failed_workflow": None,
            "missing_permission": None,
            "broken_dependency": None,
        }
        self.env.data.simulation_runs.append(sim_run)

        return SimulationResult(
            success=True,
            evidence_id=evidence_id,
            details="All workflows and dependencies satisfied under proposed policy.",
        )

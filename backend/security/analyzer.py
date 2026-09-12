"""Security policy and permission evidence analyzer."""

from __future__ import annotations

from typing import Dict, List, Optional
from backend.environment.loader import IAMEnvironment
from backend.models.evidence import (
    Evidence,
    EvidenceBundle,
    EvidenceSource,
    EvidenceState,
    EvidenceStrength,
)


class SecurityAnalyzer:
    """Deterministic analyzer building structured evidence bundles and risk assessments."""

    def __init__(self, env: IAMEnvironment) -> None:
        self.env = env

    def analyze_role(
        self, role_id: str, simulation_results: Optional[List[Dict]] = None
    ) -> Dict[str, EvidenceBundle]:
        """Examines access logs, dependencies, and simulations to construct evidence bundles for all active permissions."""
        role = self.env.get_role(role_id)
        if not role:
            return {}

        active_perms = role.active_permissions()
        logs = self.env.get_access_history(role_id=role_id)
        logged_actions = {log.action.lower() for log in logs if log.success}
        dependencies = self.env.get_service_dependencies()

        sim_results = simulation_results or []
        bundles: Dict[str, EvidenceBundle] = {}

        for perm in active_perms:
            bundle = EvidenceBundle(permission=perm)

            # 1. Access log evidence
            if perm.lower() in logged_actions:
                bundle.add_evidence(
                    Evidence(
                        source=EvidenceSource.ACCESS_LOGS,
                        permission=perm,
                        claim="Action observed in direct execution access logs",
                        strength=EvidenceStrength.HIGH,
                        state=EvidenceState.USED,
                        details={"role_id": role_id},
                    )
                )
            else:
                bundle.add_evidence(
                    Evidence(
                        source=EvidenceSource.ACCESS_LOGS,
                        permission=perm,
                        claim="Action NOT observed in access logs",
                        strength=EvidenceStrength.MEDIUM,
                        state=EvidenceState.NOT_OBSERVED,
                        details={"role_id": role_id},
                    )
                )

            # 2. Transitive dependency evidence
            matching_deps = [
                d for d in dependencies if d.required_permission.lower() == perm.lower()
            ]
            for d in matching_deps:
                bundle.add_evidence(
                    Evidence(
                        source=EvidenceSource.DEPENDENCY_GRAPH,
                        permission=perm,
                        claim=f"Hidden dependency: {d.service} -> {d.calls_service} -> {d.downstream_dependency}",
                        strength=EvidenceStrength.PROVEN,
                        state=EvidenceState.DEPENDENCY_REQUIRED,
                        details=d.model_dump(),
                    )
                )

            # 3. Simulation evidence
            for sim in sim_results:
                proposed = sim.get("proposed_permissions", [])
                passed = sim.get("success", False)
                missing = sim.get("missing_permission", "")

                # If perm was excluded from proposed policy
                if perm not in proposed:
                    if passed:
                        bundle.add_evidence(
                            Evidence(
                                source=EvidenceSource.SIMULATION,
                                permission=perm,
                                claim="Counterfactual simulation passed without this permission",
                                strength=EvidenceStrength.HIGH,
                                state=EvidenceState.PROVEN_UNNEEDED,
                                details={"simulation_passed": True, "evidence_id": sim.get("evidence_id")},
                            )
                        )
                    elif missing and missing.lower() == perm.lower():
                        bundle.add_evidence(
                            Evidence(
                                source=EvidenceSource.SIMULATION,
                                permission=perm,
                                claim=f"Counterfactual simulation FAILED when {perm} was removed",
                                strength=EvidenceStrength.HIGH,
                                state=EvidenceState.DEPENDENCY_REQUIRED,
                                details={
                                    "simulation_passed": False,
                                    "failed_workflow": sim.get("failed_workflow"),
                                    "evidence_id": sim.get("evidence_id"),
                                },
                            )
                        )

            # 4. Security rule: wildcards analysis
            if "*" in perm:
                bundle.add_evidence(
                    Evidence(
                        source=EvidenceSource.SECURITY_RULE,
                        permission=perm,
                        claim="Wildcard permission grants excessive scope across entire service API",
                        strength=EvidenceStrength.HIGH,
                        state=bundle.state,
                        details={"risk_tier": "critical", "action": perm},
                    )
                )

            bundles[perm] = bundle

        return bundles

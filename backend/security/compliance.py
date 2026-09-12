"""Compliance mapping — translate technical findings into auditor language.

Maps live role posture to CIS AWS, SOC 2, and PCI controls so both
new users (plain English) and experts (control IDs) get it instantly.
"""

from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from backend.environment.loader import IAMEnvironment
from backend.security.attack_graph import compute_attack_graph
from backend.security.temporal import classify_permissions


class ComplianceControl(BaseModel):
    framework: str
    control_id: str
    title: str
    plain_english: str
    status: str = "pass"  # pass | fail | review
    evidence: str = ""


class ComplianceReport(BaseModel):
    role_id: str
    controls: List[ComplianceControl] = Field(default_factory=list)
    passing: int = 0
    failing: int = 0
    review: int = 0


def build_compliance_report(role_id: str, env: IAMEnvironment) -> ComplianceReport:
    role = env.get_role(role_id)
    if not role:
        raise ValueError(f"Role '{role_id}' not found.")
    perms = role.active_permissions()
    wildcards = [p for p in perms if "*" in p]
    graph = compute_attack_graph(role_id, env)
    temporal = classify_permissions(role_id, env)

    controls: List[ComplianceControl] = []

    # CIS AWS 1.20 — least privilege
    controls.append(
        ComplianceControl(
            framework="CIS AWS v1.5",
            control_id="1.20",
            title="Ensure IAM policies follow least privilege",
            plain_english="Nobody should hold master keys they never use.",
            status="fail" if wildcards else "pass",
            evidence=f"Wildcard grants: {wildcards or 'none'}; active={len(perms)}",
        )
    )
    # SOC 2 CC6.1 — access restricted
    controls.append(
        ComplianceControl(
            framework="SOC 2",
            control_id="CC6.1",
            title="Access restricted to authorized boundaries",
            plain_english="If this login leaks, what rooms can the thief enter?",
            status="fail" if graph.protected_reachable else "pass",
            evidence=f"Protected resources reachable: {graph.protected_reachable or 'none'}",
        )
    )
    # PCI DSS 7.1.2 — access by job need
    dead = [f.permission for f in temporal.findings if f.classification == "DEAD"]
    controls.append(
        ComplianceControl(
            framework="PCI DSS v4",
            control_id="7.1.2",
            title="Access assigned by job need, reviewed",
            plain_english="Unused permissions get removed — except rare-but-critical ones we can prove.",
            status="review" if dead else "pass",
            evidence=f"Unused with no dependency: {dead or 'none'}; rare-but-critical retained: {temporal.retain}",
        )
    )
    # SOC 2 CC7.2 — monitoring + rollback
    controls.append(
        ComplianceControl(
            framework="SOC 2",
            control_id="CC7.2",
            title="Anomalies monitored, changes reversible",
            plain_english="Every change is simulated first and can be undone in one click.",
            status="pass",
            evidence="Counterfactual simulation + atomic rollback + hash-chained audit trail",
        )
    )

    return ComplianceReport(
        role_id=role_id,
        controls=controls,
        passing=sum(1 for c in controls if c.status == "pass"),
        failing=sum(1 for c in controls if c.status == "fail"),
        review=sum(1 for c in controls if c.status == "review"),
    )


__all__ = ["ComplianceControl", "ComplianceReport", "build_compliance_report"]

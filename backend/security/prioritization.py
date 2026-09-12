"""Fleet risk queue — Wiz-style prioritized list across all roles.

Scores every role so security teams fix the riskiest identity first,
not alphabetically. Pure deterministic function of existing engines.
"""

from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from backend.environment.loader import IAMEnvironment
from backend.security.attack_graph import compute_attack_graph
from backend.security.temporal import classify_permissions


class FleetRisk(BaseModel):
    role_id: str
    risk_score: float = 0.0
    risk_level: str = "LOW"
    wildcards: List[str] = Field(default_factory=list)
    protected_reachable: List[str] = Field(default_factory=list)
    dead_permissions: List[str] = Field(default_factory=list)
    recommended_action: str = ""
    estimated_exposure: str = ""  # plain-English impact for execs


class FleetQueue(BaseModel):
    risks: List[FleetRisk] = Field(default_factory=list)
    total_roles: int = 0
    critical_count: int = 0


def build_fleet_queue(env: IAMEnvironment) -> FleetQueue:
    risks: List[FleetRisk] = []
    for role in env.data.roles:
        perms = role.active_permissions()
        wildcards = [p for p in perms if "*" in p]
        try:
            graph = compute_attack_graph(role.id, env)
        except ValueError:
            continue
        try:
            temporal = classify_permissions(role.id, env)
            dead = [f.permission for f in temporal.findings if f.classification == "DEAD"]
        except ValueError:
            dead = []
        # Deterministic score: protected reachability dominates, then wildcards, then dead weight
        score = min(
            100.0,
            len(graph.protected_reachable) * 25.0 + len(wildcards) * 12.0 + len(dead) * 4.0 + graph.risk_score * 0.2,
        )
        level = "CRITICAL" if score >= 75 else ("HIGH" if score >= 50 else ("MEDIUM" if score >= 25 else "LOW"))
        if level in ("CRITICAL", "HIGH"):
            action = f"Run least-privilege remediation now; remove {wildcards or dead or ['excess grants']}"
        elif dead:
            action = f"Schedule cleanup of unused: {dead}"
        else:
            action = "Monitor; posture healthy"
        exposure = (
            f"Compromise reaches {len(graph.protected_reachable)} protected resource(s)"
            if graph.protected_reachable
            else "No protected resources reachable"
        )
        risks.append(
            FleetRisk(
                role_id=role.id,
                risk_score=round(score, 2),
                risk_level=level,
                wildcards=wildcards,
                protected_reachable=graph.protected_reachable,
                dead_permissions=dead,
                recommended_action=action,
                estimated_exposure=exposure,
            )
        )
    risks.sort(key=lambda r: r.risk_score, reverse=True)
    return FleetQueue(
        risks=risks,
        total_roles=len(risks),
        critical_count=sum(1 for r in risks if r.risk_level in ("CRITICAL", "HIGH")),
    )


__all__ = ["FleetRisk", "FleetQueue", "build_fleet_queue"]

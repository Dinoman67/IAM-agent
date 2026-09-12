"""Attack-path graph — 'what can an attacker reach if this role is stolen?'."""

from __future__ import annotations

import fnmatch
from typing import Any, Dict, List

from pydantic import BaseModel, Field

from backend.environment.loader import IAMEnvironment


class AttackNode(BaseModel):
    id: str
    kind: str  # role | permission | resource
    label: str
    risk: str = "low"  # low|medium|high|critical
    protected: bool = False


class AttackEdge(BaseModel):
    from_id: str
    to_id: str
    via: str = ""


class AttackPath(BaseModel):
    path: List[str]
    reaches_protected: bool = False
    severity: str = "low"


class AttackGraph(BaseModel):
    role_id: str
    nodes: List[AttackNode] = Field(default_factory=list)
    edges: List[AttackEdge] = Field(default_factory=list)
    paths: List[AttackPath] = Field(default_factory=list)
    reachable_resources: List[str] = Field(default_factory=list)
    protected_reachable: List[str] = Field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "LOW"
    paths_blocked_by_proposal: int = 0


def _perm_matches_resource(perm: str, required: List[str]) -> bool:
    for r in required:
        if perm == r or fnmatch.fnmatch(r, perm) or fnmatch.fnmatch(perm, r):
            return True
        # wildcard grant like ec2:* matches any ec2: X required for resource type ec2
        if perm.endswith(":*") and r.startswith(perm[:-2]):
            return True
    return False


def compute_attack_graph(role_id: str, env: IAMEnvironment) -> AttackGraph:
    role = env.get_role(role_id)
    if not role:
        raise ValueError(f"Role '{role_id}' not found.")
    perms = role.active_permissions()
    resources = list(env.data.resources)

    perm_risk = {p.id: p.risk_level for p in env.data.permissions}
    nodes: List[AttackNode] = [AttackNode(id=f"role:{role_id}", kind="role", label=role_id, risk="high")]
    edges: List[AttackEdge] = []
    paths: List[AttackPath] = []
    reachable: List[str] = []
    protected_hit: List[str] = []

    for perm in perms:
        risk = perm_risk.get(perm, "critical" if "*" in perm else "medium")
        nodes.append(AttackNode(id=f"perm:{perm}", kind="permission", label=perm, risk=risk))
        edges.append(AttackEdge(from_id=f"role:{role_id}", to_id=f"perm:{perm}", via="grants"))
        for res in resources:
            if _perm_matches_resource(perm, res.required_permissions):
                rid = f"res:{res.id}"
                if not any(n.id == rid for n in nodes):
                    nodes.append(
                        AttackNode(
                            id=rid,
                            kind="resource",
                            label=res.arn,
                            risk="critical" if res.is_protected else "medium",
                            protected=res.is_protected,
                        )
                    )
                edges.append(AttackEdge(from_id=f"perm:{perm}", to_id=rid, via="can-access"))
                apath = [role_id, perm, res.arn]
                paths.append(
                    AttackPath(
                        path=apath,
                        reaches_protected=res.is_protected,
                        severity="critical" if res.is_protected else ("high" if "*" in perm else "medium"),
                    )
                )
                if res.arn not in reachable:
                    reachable.append(res.arn)
                if res.is_protected and res.arn not in protected_hit:
                    protected_hit.append(res.arn)

    # Deterministic risk score: protected reachability dominates
    score = min(100.0, len(protected_hit) * 30.0 + len(reachable) * 5.0 + sum(1 for p in perms if "*" in p) * 10.0)
    level = "CRITICAL" if score >= 75 or len(protected_hit) >= 2 else ("HIGH" if score >= 50 or protected_hit else ("MEDIUM" if score >= 25 else "LOW"))
    return AttackGraph(
        role_id=role_id,
        nodes=nodes,
        edges=edges,
        paths=paths,
        reachable_resources=reachable,
        protected_reachable=protected_hit,
        risk_score=round(score, 2),
        risk_level=level,
    )


def paths_blocked(original: AttackGraph, proposed_permissions: List[str], env: IAMEnvironment) -> int:
    """Count attack paths eliminated by moving to proposed_permissions (pure function)."""
    role = env.get_role(original.role_id)
    if not role:
        return 0
    # Build proposed reachability quickly
    blocked = 0
    resources = list(env.data.resources)
    orig_set = set(role.active_permissions())
    removed = orig_set - set(proposed_permissions)
    for path in original.paths:
        # path = [role, perm, arn]; blocked if the enabling perm was removed
        if len(path.path) >= 2 and path.path[1] in removed:
            # confirm no other remaining perm still reaches same resource
            arn = path.path[2]
            still_reachable = False
            for perm in proposed_permissions:
                for res in resources:
                    if res.arn == arn and _perm_matches_resource(perm, res.required_permissions):
                        still_reachable = True
            if not still_reachable:
                blocked += 1
    return blocked


__all__ = ["AttackGraph", "AttackNode", "AttackEdge", "AttackPath", "compute_attack_graph", "paths_blocked"]

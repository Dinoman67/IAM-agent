"""Attacker duel — red-team climax: old policy vs remediated policy.

The attacker steals the role under policy A, then under policy B.
Same stolen credential, different blast radius. Deterministic, no theater:
reachability is computed by the same attack-graph engine as the console.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field

from backend.environment.loader import IAMEnvironment
from backend.security.attack_graph import compute_attack_graph_for_permissions


class DuelRound(BaseModel):
    policy: str = Field(..., description="'before' (baseline v1) or 'after' (remediated)")
    permissions: List[str] = Field(default_factory=list)
    reachable_protected: List[str] = Field(default_factory=list)
    reachable_count: int = 0
    risk_score: float = 0.0
    verdict: str = "HELD"  # BREACHED (protected reachable) | HELD


class AttackerDuel(BaseModel):
    role_id: str
    before: DuelRound
    after: DuelRound
    protected_saved: List[str] = Field(default_factory=list)
    headline: str = ""


def run_duel(
    role_id: str,
    env: IAMEnvironment,
    before_permissions: Optional[List[str]] = None,
    after_permissions: Optional[List[str]] = None,
) -> AttackerDuel:
    role = env.get_role(role_id)
    if not role:
        raise ValueError(f"Role '{role_id}' not found.")
    if before_permissions is None:
        v1 = next((v for v in role.policy_versions if v.version_id == "v1"), None)
        before_permissions = list(v1.permissions) if v1 else role.active_permissions()
    if after_permissions is None:
        after_permissions = role.active_permissions()

    def _round(name: str, perms: List[str]) -> DuelRound:
        g = compute_attack_graph_for_permissions(role_id, perms, env)
        return DuelRound(
            policy=name,
            permissions=sorted(perms),
            reachable_protected=g.protected_reachable,
            reachable_count=len(g.reachable_resources),
            risk_score=g.risk_score,
            verdict="BREACHED" if g.protected_reachable else "HELD",
        )

    before = _round("before", before_permissions)
    after = _round("after", after_permissions)
    saved = sorted(set(before.reachable_protected) - set(after.reachable_protected))
    if set(before_permissions) == set(after_permissions):
        headline = "Policies identical — run remediation first, then duel the old key card against the new one."
    elif saved:
        headline = f"Attacker with the OLD key card reaches {len(before.reachable_protected)} protected resource(s); with the NEW card: {len(after.reachable_protected)}. {len(saved)} crown jewel(s) saved."
    elif before.verdict == "HELD":
        headline = "Baseline already held — nothing for the attacker to take."
    else:
        headline = "Remediation did not reduce attacker reach — investigate before merging."
    return AttackerDuel(role_id=role_id, before=before, after=after, protected_saved=saved, headline=headline)


__all__ = ["DuelRound", "AttackerDuel", "run_duel"]

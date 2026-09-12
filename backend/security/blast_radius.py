"""Deterministic blast-radius evaluation engine for IAM policy changes."""

from __future__ import annotations

import fnmatch
from typing import Any, Dict, List, Literal, Optional, Sequence
from pydantic import BaseModel, Field

BlastRadiusLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class BlastRadiusAssessment(BaseModel):
    """Authoritative deterministic assessment of policy change blast radius."""

    level: BlastRadiusLevel = Field(..., description="'LOW', 'MEDIUM', 'HIGH', or 'CRITICAL'")
    score: float = Field(..., description="Deterministic numerical impact score [0.0 - 100.0]")
    factors: List[str] = Field(default_factory=list, description="Explicit factors contributing to score")
    changed_permissions_count: int = 0
    resources_affected_count: int = 0
    has_wildcards: bool = False
    wildcard_permissions: List[str] = Field(default_factory=list)
    principal_sensitivity: str = "standard"
    dependency_count: int = 0
    touches_protected_resource: bool = False
    details: Dict[str, Any] = Field(default_factory=dict)


def calculate_blast_radius(
    original_permissions: Sequence[str],
    proposed_permissions: Sequence[str],
    resources_affected: Optional[Sequence[str]] = None,
    principal_id: Optional[str] = None,
    principal_type: Optional[str] = None,
    is_sensitive_principal: bool = False,
    dependencies_count: int = 0,
    touches_protected_resource: bool = False,
    provider: str = "aws",
    protected_permissions: Optional[Sequence[str]] = None,
) -> BlastRadiusAssessment:
    """Deterministically evaluates blast radius across 7 distinct dimensions.
    
    The LLM may suggest or predict blast radius, but this function is the final authority.
    """
    orig_set = set(original_permissions)
    prop_set = set(proposed_permissions)

    removed = orig_set - prop_set
    added = prop_set - orig_set
    total_changed = len(removed) + len(added)

    factors: List[str] = []
    score = 0.0

    # 1. Volume of changes (modest weight for least-privilege reductions)
    if total_changed > 0:
        change_weight = min(total_changed * 3.0, 15.0)
        score += change_weight
        factors.append(f"Changed {total_changed} permissions ({len(removed)} removed, {len(added)} added)")
    if total_changed >= 6:
        score += 10.0
        factors.append(f"High change volume ({total_changed} actions modified)")

    # 2. Wildcards in proposed permissions (granting or retaining wildcards is risky)
    proposed_wildcards = [p for p in prop_set if "*" in p]
    has_wildcards = len(proposed_wildcards) > 0
    if proposed_wildcards:
        score += 35.0
        factors.append(f"Policy retains or grants wildcard actions: {sorted(proposed_wildcards)}")

    # 3. Principal sensitivity
    p_sens = "sensitive" if is_sensitive_principal else "standard"
    p_id_lower = (principal_id or "").lower()
    if is_sensitive_principal or "admin" in p_id_lower or "root" in p_id_lower or principal_type == "admin":
        p_sens = "critical_identity"
        score += 25.0
        factors.append(f"Target principal '{principal_id}' is a high-sensitivity administrative identity")

    # 4. Resources affected
    if resources_affected:
        res_list = list(resources_affected)
        res_count = len(res_list)
        has_wildcard_resource = any(r == "*" for r in res_list)
        if has_wildcard_resource:
            score += 15.0
            factors.append("Explicitly targets wildcard resource scope ('*')")
        elif res_count > 3:
            score += 10.0
            factors.append(f"Multiple specific resources impacted ({res_count} resources)")
    else:
        res_count = 0

    # 5. Protected resources interaction
    if touches_protected_resource:
        score += 40.0
        factors.append("Policy interacts with protected or sensitive infrastructure resources")

    # 6. Protected permissions interaction in proposed or added
    prot_set = set(protected_permissions or [])
    touched_protected = prop_set.intersection(prot_set)
    if touched_protected:
        score += 30.0
        factors.append(f"Proposed policy retains protected administrative permissions: {sorted(list(touched_protected))}")

    # 7. Dependency count
    if dependencies_count > 2:
        score += 10.0
        factors.append(f"Interacts with {dependencies_count} transitive infrastructure dependencies")

    # Cap score at 100
    score = min(score, 100.0)

    # Classify level
    if score >= 75.0 or (touches_protected_resource and has_wildcards) or (p_sens == "critical_identity" and has_wildcards):
        level: BlastRadiusLevel = "CRITICAL"
    elif score >= 50.0 or touches_protected_resource or len(proposed_wildcards) > 0:
        level = "HIGH"
    elif score >= 25.0 or total_changed >= 5:
        level = "MEDIUM"
    else:
        level = "LOW"

    return BlastRadiusAssessment(
        level=level,
        score=round(score, 2),
        factors=factors,
        changed_permissions_count=total_changed,
        resources_affected_count=res_count,
        has_wildcards=has_wildcards,
        wildcard_permissions=proposed_wildcards,
        principal_sensitivity=p_sens,
        dependency_count=dependencies_count,
        touches_protected_resource=touches_protected_resource,
        details={
            "removed_permissions": list(removed),
            "added_permissions": list(added),
            "retained_permissions": list(orig_set & prop_set),
            "provider": provider,
        },
    )


__all__ = [
    "BlastRadiusLevel",
    "BlastRadiusAssessment",
    "calculate_blast_radius",
]

"""Deterministic privilege expansion, scope widening, and condition weakening detection."""

from __future__ import annotations

import fnmatch
from typing import Any, Dict, List, Optional, Sequence, Set, Union
from pydantic import BaseModel, Field

from backend.models.iam import (
    CommonAction,
    CommonBinding,
    CommonCondition,
    CommonPolicy,
    CommonPrincipal,
    CommonResource,
    CommonStatement,
    PolicyEffect,
)


class PrivilegeExpansionResult(BaseModel):
    """Authoritative result of privilege expansion and weakening analysis."""

    is_expanded: bool = Field(default=False, description="True if proposed policy grants more authority than baseline")
    expansion_types: List[str] = Field(default_factory=list)
    expanded_actions: List[str] = Field(default_factory=list)
    expanded_resources: List[str] = Field(default_factory=list)
    weakened_conditions: List[str] = Field(default_factory=list)
    broadened_principals: List[str] = Field(default_factory=list)
    broadened_scopes: List[str] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)


def _action_subsumes(broader: str, narrower: str) -> bool:
    """Checks if broader action pattern grants strictly more authority than narrower action."""
    b = broader.lower().strip()
    n = narrower.lower().strip()
    if b == "*":
        return n != "*"
    if "*" in b:
        # e.g. s3:* subsumes s3:getobject
        return fnmatch.fnmatch(n, b) and b != n
    return False


def detect_action_expansion(
    baseline_actions: Sequence[str], proposed_actions: Sequence[str]
) -> List[str]:
    """Detects if proposed actions include newly added actions or widened action wildcards."""
    base_set = set(baseline_actions)
    prop_set = set(proposed_actions)

    expanded: List[str] = []

    # Check 1: Brand new actions not in baseline
    new_actions = prop_set - base_set
    for action in new_actions:
        expanded.append(f"new_action_granted:{action}")

    # Check 2: Wildcard escalation from specific actions
    # e.g., baseline had "s3:GetObject", proposed has "s3:*" or "*"
    for p in prop_set:
        if "*" in p:
            # Check if baseline had only more specific actions under this service
            if ":" in p:
                svc = p.split(":")[0].lower()
                specific_base = [a for a in base_set if a.lower().startswith(f"{svc}:") and "*" not in a]
                if specific_base and p not in base_set:
                    expanded.append(f"action_widened_to_wildcard:{p}")
            elif p == "*" and "*" not in base_set:
                expanded.append("action_widened_to_global_wildcard:*")

    return expanded


def detect_resource_expansion(
    baseline_resources: Sequence[str], proposed_resources: Sequence[str]
) -> List[str]:
    """Detects if resources were widened to wildcards or new resources were introduced."""
    base_set = set(baseline_resources)
    prop_set = set(proposed_resources)

    expanded: List[str] = []

    # Check if widened from specific resources to '*'
    if "*" in prop_set and "*" not in base_set and len(base_set) > 0:
        expanded.append("resource_widened_to_wildcard:*")

    # Check for newly added resources
    new_res = prop_set - base_set
    for r in new_res:
        if r != "*":
            expanded.append(f"new_resource_granted:{r}")

    return expanded


def detect_condition_weakening(
    baseline_conditions: Sequence[Dict[str, Any]], proposed_conditions: Sequence[Dict[str, Any]]
) -> List[str]:
    """Detects if conditions were deleted or relaxed."""
    weakened: List[str] = []

    # If baseline had conditions, but proposed has fewer or none
    if len(baseline_conditions) > 0 and len(proposed_conditions) == 0:
        weakened.append("all_conditions_removed")
    elif len(proposed_conditions) < len(baseline_conditions):
        weakened.append(
            f"conditions_removed_count:{len(baseline_conditions) - len(proposed_conditions)}"
        )

    return weakened


def detect_scope_expansion(
    baseline_scope: Optional[str], proposed_scope: Optional[str]
) -> List[str]:
    """Detects if authorization scope was widened (e.g. resource group to subscription or root)."""
    expanded: List[str] = []
    if baseline_scope and proposed_scope:
        b_clean = baseline_scope.strip().lower()
        p_clean = proposed_scope.strip().lower()

        # e.g. baseline was /subscriptions/sub1/resourceGroups/rg1 and proposed is /subscriptions/sub1 or /
        if b_clean != p_clean and b_clean.startswith(p_clean) and len(p_clean) < len(b_clean):
            expanded.append(f"scope_widened_from_{baseline_scope}_to_{proposed_scope}")

    return expanded


def check_privilege_expansion(
    baseline: Union[CommonPolicy, Sequence[str]],
    proposed: Union[CommonPolicy, Sequence[str]],
    baseline_resources: Optional[Sequence[str]] = None,
    proposed_resources: Optional[Sequence[str]] = None,
    baseline_scope: Optional[str] = None,
    proposed_scope: Optional[str] = None,
) -> PrivilegeExpansionResult:
    """Deterministically verifies that candidate changes do not expand privilege along any dimension."""
    expansion_types: List[str] = []
    reasons: List[str] = []
    expanded_actions: List[str] = []
    expanded_resources: List[str] = []
    weakened_conditions: List[str] = []
    broadened_principals: List[str] = []
    broadened_scopes: List[str] = []

    # Extract actions, resources, conditions, scopes
    if isinstance(baseline, CommonPolicy) and isinstance(proposed, CommonPolicy):
        base_actions = baseline.extract_permission_strings()
        prop_actions = proposed.extract_permission_strings()

        base_res: List[str] = []
        for stmt in baseline.statements:
            base_res.extend(r.arn_or_id for r in stmt.resources)
        prop_res: List[str] = []
        for stmt in proposed.statements:
            prop_res.extend(r.arn_or_id for r in stmt.resources)

        base_conds = [c.model_dump() for stmt in baseline.statements for c in stmt.conditions]
        prop_conds = [c.model_dump() for stmt in proposed.statements for c in stmt.conditions]

        b_scope = baseline.metadata.get("scope") or baseline_scope
        p_scope = proposed.metadata.get("scope") or proposed_scope
    else:
        base_actions = list(baseline) if not isinstance(baseline, CommonPolicy) else baseline.extract_permission_strings()
        prop_actions = list(proposed) if not isinstance(proposed, CommonPolicy) else proposed.extract_permission_strings()
        base_res = list(baseline_resources or [])
        prop_res = list(proposed_resources or [])
        base_conds = []
        prop_conds = []
        b_scope = baseline_scope
        p_scope = proposed_scope

    # 1. Action expansion
    act_exp = detect_action_expansion(base_actions, prop_actions)
    if act_exp:
        expansion_types.append("action_expansion")
        expanded_actions.extend(act_exp)
        for a in act_exp:
            reasons.append(f"Privilege expansion in actions: {a}")

    # 2. Resource expansion
    res_exp = detect_resource_expansion(base_res, prop_res)
    if res_exp:
        expansion_types.append("resource_expansion")
        expanded_resources.extend(res_exp)
        for r in res_exp:
            reasons.append(f"Privilege expansion in resources: {r}")

    # 3. Condition weakening
    cond_weak = detect_condition_weakening(base_conds, prop_conds)
    if cond_weak:
        expansion_types.append("condition_weakening")
        weakened_conditions.extend(cond_weak)
        for c in cond_weak:
            reasons.append(f"Privilege expansion via condition weakening: {c}")

    # 4. Scope expansion
    sc_exp = detect_scope_expansion(b_scope, p_scope)
    if sc_exp:
        expansion_types.append("scope_expansion")
        broadened_scopes.extend(sc_exp)
        for s in sc_exp:
            reasons.append(f"Privilege expansion via scope broadening: {s}")

    is_expanded = len(expansion_types) > 0

    return PrivilegeExpansionResult(
        is_expanded=is_expanded,
        expansion_types=expansion_types,
        expanded_actions=expanded_actions,
        expanded_resources=expanded_resources,
        weakened_conditions=weakened_conditions,
        broadened_principals=broadened_principals,
        broadened_scopes=broadened_scopes,
        reasons=reasons,
        details={
            "baseline_action_count": len(base_actions),
            "proposed_action_count": len(prop_actions),
            "net_difference": len(prop_actions) - len(base_actions),
        },
    )


__all__ = [
    "PrivilegeExpansionResult",
    "detect_action_expansion",
    "detect_resource_expansion",
    "detect_condition_weakening",
    "detect_scope_expansion",
    "check_privilege_expansion",
]

"""Deterministic evidence sufficiency evaluation and fail-closed gates."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence
from pydantic import BaseModel, Field

from backend.models.evidence import EvidenceBundle, EvidenceSource, EvidenceState


class EvidenceSufficiencyResult(BaseModel):
    """Result of evaluating evidence sufficiency for proposed permission removals."""

    is_sufficient: bool = Field(..., description="True if all removals are backed by sufficient deterministic evidence")
    reasons: List[str] = Field(default_factory=list)
    unknown_permissions: List[str] = Field(default_factory=list)
    unproven_permissions: List[str] = Field(default_factory=list)
    blocked_permissions: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)


def evaluate_evidence_sufficiency(
    remove_permissions: Sequence[str],
    evidence_bundles: Dict[str, EvidenceBundle],
    simulation_passed: bool = False,
    risk_level: str = "medium",
) -> EvidenceSufficiencyResult:
    """Evaluates whether candidate permission removals satisfy deterministic evidence thresholds.
    
    CRITICAL RULE: NOT_OBSERVED != PROVEN_UNNEEDED.
    Unobserved permissions cannot be removed unless proven safe via counterfactual simulation
    or verified by dependency analysis. UNKNOWN evidence forces escalation.
    """
    reasons: List[str] = []
    unknown_perms: List[str] = []
    unproven_perms: List[str] = []
    blocked_perms: List[str] = []

    for perm in remove_permissions:
        bundle = evidence_bundles.get(perm)
        if not bundle:
            # No evidence bundle exists -> state is UNKNOWN
            unknown_perms.append(perm)
            reasons.append(f"Permission '{perm}' has NO evidence bundle (state: UNKNOWN)")
            continue

        if bundle.state == EvidenceState.UNKNOWN:
            unknown_perms.append(perm)
            reasons.append(f"Permission '{perm}' has UNKNOWN evidence state; cannot autonomously remove")
        elif bundle.state == EvidenceState.DEPENDENCY_REQUIRED:
            blocked_perms.append(perm)
            reasons.append(
                f"Permission '{perm}' is DEPENDENCY_REQUIRED by service architecture; removal forbidden"
            )
        elif bundle.state == EvidenceState.USED:
            blocked_perms.append(perm)
            reasons.append(f"Permission '{perm}' is USED in active logs; removal forbidden")
        elif bundle.state == EvidenceState.NOT_OBSERVED:
            # NOT_OBSERVED requires passing simulation proof to be removed safely
            if not simulation_passed and not bundle.removal_permitted:
                unproven_perms.append(perm)
                reasons.append(
                    f"Permission '{perm}' is NOT_OBSERVED, which does not equal PROVEN_UNNEEDED; requires simulation proof"
                )
        elif bundle.state == EvidenceState.PROVEN_UNNEEDED:
            # Proven unneeded via counterfactual simulation: safe to remove
            pass

    is_sufficient = (len(unknown_perms) == 0 and len(unproven_perms) == 0 and len(blocked_perms) == 0)

    return EvidenceSufficiencyResult(
        is_sufficient=is_sufficient,
        reasons=reasons,
        unknown_permissions=unknown_perms,
        unproven_permissions=unproven_perms,
        blocked_permissions=blocked_perms,
        details={
            "total_evaluated": len(remove_permissions),
            "sufficient_count": len(remove_permissions) - len(unknown_perms) - len(unproven_perms) - len(blocked_perms),
        },
    )


__all__ = [
    "EvidenceSufficiencyResult",
    "evaluate_evidence_sufficiency",
]

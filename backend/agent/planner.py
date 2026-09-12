"""Explicit planning system for IAM least-privilege remediation."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

PlanStatus = Literal["draft", "active", "replanning", "verified", "failed", "abandoned"]
RiskLevel = Literal["low", "medium", "high", "critical"]


class AgentPlan(BaseModel):
    """Structured plan tracking objective, assumptions, candidates, and verification."""

    objective: str = Field(..., description="High-level security and operational objective")
    assumptions: List[str] = Field(
        default_factory=list, description="Working hypotheses and system assumptions"
    )
    candidate_changes: List[Dict[str, Any]] = Field(
        default_factory=list, description="List of proposed permission removals/reductions"
    )
    required_evidence: List[str] = Field(
        default_factory=list, description="Evidence requirements before applying changes"
    )
    verification_requirements: List[str] = Field(
        default_factory=list, description="Mandatory tests and invariants for signoff"
    )
    risk_level: RiskLevel = Field(
        default="medium", description="Estimated operational/security blast radius"
    )
    status: PlanStatus = Field(
        default="draft", description="Current lifecycle status of the plan"
    )
    version: int = Field(default=1, description="Plan revision number incremented on replans")
    replan_reason: Optional[str] = Field(
        default=None, description="Reason triggering the latest plan revision"
    )

    def revise(
        self,
        replan_reason: str,
        new_candidate_changes: Optional[List[Dict[str, Any]]] = None,
        new_assumptions: Optional[List[str]] = None,
        new_required_evidence: Optional[List[str]] = None,
        new_risk_level: Optional[RiskLevel] = None,
    ) -> AgentPlan:
        """Increment plan version and update properties after counterfactual failure or new evidence."""
        self.version += 1
        self.status = "replanning"
        self.replan_reason = replan_reason
        if new_candidate_changes is not None:
            self.candidate_changes = new_candidate_changes
        if new_assumptions is not None:
            self.assumptions = new_assumptions
        if new_required_evidence is not None:
            self.required_evidence = new_required_evidence
        if new_risk_level is not None:
            self.risk_level = new_risk_level
        return self

    def mark_active(self) -> None:
        self.status = "active"

    def mark_verified(self) -> None:
        self.status = "verified"

    def mark_failed(self, reason: Optional[str] = None) -> None:
        self.status = "failed"
        if reason:
            self.replan_reason = reason

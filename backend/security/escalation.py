"""Structured escalation mechanisms and error models for autonomous IAM remediation."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EscalationReason(str, Enum):
    """Categorical reasons requiring autonomy halt and human escalation."""

    HIGH_RISK = "high_risk"
    CRITICAL_PERMISSION = "critical_permission"
    UNSUPPORTED_PROVIDER_OPERATION = "unsupported_provider_operation"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    SIMULATION_UNAVAILABLE = "simulation_unavailable"
    STALE_STATE = "stale_state"
    VERIFICATION_FAILURE = "verification_failure"
    ROLLBACK_FAILURE = "rollback_failure"
    REPEATED_FAILED_ACTIONS = "repeated_failed_actions"
    CROSS_TENANT_VIOLATION = "cross_tenant_violation"
    PRIVILEGE_EXPANSION = "privilege_expansion"
    BUDGET_EXHAUSTED = "budget_exhausted"
    SECURITY_INVARIANT_VIOLATION = "security_invariant_violation"


class EscalationRecord(BaseModel):
    """Structured human escalation artifact explaining why autonomy stopped and recommended action."""

    escalation_id: str = Field(default_factory=lambda: f"esc-{uuid.uuid4().hex[:8]}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    reason_code: EscalationReason = Field(..., description="Categorical reason for human escalation")
    summary: str = Field(..., description="High-level description of why autonomy stopped")
    recommended_action: str = Field(
        ..., description="Actionable recommendation for human administrator or security engineer"
    )
    role_id: Optional[str] = None
    provider: str = Field(default="aws")
    required_reviewers: List[str] = Field(default_factory=lambda: ["IAM-Security-Admin"])
    details: Dict[str, Any] = Field(default_factory=dict)


def build_escalation(
    reason_code: EscalationReason,
    summary: str,
    role_id: Optional[str] = None,
    provider: str = "aws",
    recommended_action: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> EscalationRecord:
    """Helper constructing a strongly-typed EscalationRecord with standard recommendations."""
    default_recommendations = {
        EscalationReason.HIGH_RISK: "Review candidate policy diff in staging environment and obtain security signoff.",
        EscalationReason.CRITICAL_PERMISSION: "Confirm whether administrative capabilities should be detached or retained.",
        EscalationReason.UNSUPPORTED_PROVIDER_OPERATION: "Execute manual validation using native cloud provider CLI/console.",
        EscalationReason.INSUFFICIENT_EVIDENCE: "Wait for additional telemetry observation window or conduct manual user review.",
        EscalationReason.SIMULATION_UNAVAILABLE: "Provider does not support counterfactual simulation; run canary deployment manually.",
        EscalationReason.STALE_STATE: "Re-read current active policy state and regenerate candidate remediation plan.",
        EscalationReason.VERIFICATION_FAILURE: "Inspect failing operational workflows and investigate missing permissions.",
        EscalationReason.ROLLBACK_FAILURE: "CRITICAL: Automated rollback failed. Manually restore previous IAM policy revision immediately.",
        EscalationReason.REPEATED_FAILED_ACTIONS: "Loop detected: tool failed repeatedly without progress. Investigate environment errors.",
        EscalationReason.CROSS_TENANT_VIOLATION: "Verify cross-tenant boundary configurations and reject unauthorized cross-account access.",
        EscalationReason.PRIVILEGE_EXPANSION: "Candidate proposal broadens authority; reject and rewrite least-privilege plan.",
        EscalationReason.BUDGET_EXHAUSTED: "Agent exceeded budget limit (runtime, iterations, or tool calls). Review complexity.",
        EscalationReason.SECURITY_INVARIANT_VIOLATION: "Security Kernel blocked proposal violating hard security invariants.",
    }

    rec = recommended_action or default_recommendations.get(reason_code, "Review audit trail and proceed manually.")
    return EscalationRecord(
        reason_code=reason_code,
        summary=summary,
        recommended_action=rec,
        role_id=role_id,
        provider=provider,
        details=details or {},
    )


__all__ = [
    "EscalationReason",
    "EscalationRecord",
    "build_escalation",
]

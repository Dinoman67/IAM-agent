"""Explicit deterministic security invariants and decision schemas for IAM remediation."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

GateDecision = Literal["allow", "deny", "escalate"]


class SecurityInvariant(BaseModel):
    """Structured security invariant governing autonomous remediation decisions."""

    id: str = Field(..., description="Unique invariant identifier, e.g. 'NO_PRIVILEGE_EXPANSION'")
    severity: Literal["critical", "high", "medium", "low"] = Field(
        default="critical", description="Severity classification of the invariant"
    )
    category: str = Field(
        default="security",
        description="Invariant domain: 'privilege', 'resource', 'isolation', 'state', 'evidence', 'verification', 'risk'",
    )
    description: str = Field(..., description="Clear explanation of the invariant rule")
    mitigation: Optional[str] = Field(
        default=None, description="Recommended remediation or escalation guidance if violated"
    )


# Standard Security Invariants
INVARIANT_NO_PRIVILEGE_EXPANSION = SecurityInvariant(
    id="NO_PRIVILEGE_EXPANSION",
    severity="critical",
    category="privilege",
    description="Proposed policy changes must never expand permissions, broaden resources, widen principals, or weaken conditions beyond the baseline.",
    mitigation="Remove unauthorized actions or resource wildcards from candidate policy.",
)

INVARIANT_NO_PROTECTED_PERMISSION_MUTATION = SecurityInvariant(
    id="NO_PROTECTED_PERMISSION_MUTATION",
    severity="critical",
    category="privilege",
    description="Protected administrative permissions (e.g. iam:*, admin wildcards) cannot be granted or mutated without explicit human approval.",
    mitigation="Escalate for human security administrator review and approval.",
)

INVARIANT_NO_PROTECTED_RESOURCE_EXPOSURE = SecurityInvariant(
    id="NO_PROTECTED_RESOURCE_EXPOSURE",
    severity="critical",
    category="resource",
    description="Proposed policy must never grant access to protected sensitive infrastructure (e.g. PII tables, root keys, audit logs).",
    mitigation="Restrict resource scope or eliminate permissions granting access to protected resources.",
)

INVARIANT_NO_CROSS_PROVIDER_MUTATION = SecurityInvariant(
    id="NO_CROSS_PROVIDER_MUTATION",
    severity="critical",
    category="isolation",
    description="Policy mutations cannot cross cloud provider boundaries (e.g. applying Azure assignments to AWS).",
    mitigation="Route policy artifact to matching cloud provider adapter.",
)

INVARIANT_NO_CROSS_TENANT_MUTATION = SecurityInvariant(
    id="NO_CROSS_TENANT_MUTATION",
    severity="critical",
    category="isolation",
    description="Policy mutations cannot cross tenant, account, project, or subscription isolation boundaries.",
    mitigation="Scope candidate policy strictly within the designated tenant boundary.",
)

INVARIANT_NO_STALE_STATE_MUTATION = SecurityInvariant(
    id="NO_STALE_STATE_MUTATION",
    severity="high",
    category="state",
    description="Policy changes cannot be applied against outdated policy versions (optimistic concurrency control).",
    mitigation="Refresh active policy state, invalidate existing plan, and re-simulate.",
)

INVARIANT_NO_MUTATION_WITHOUT_EVIDENCE = SecurityInvariant(
    id="NO_MUTATION_WITHOUT_EVIDENCE",
    severity="high",
    category="evidence",
    description="Permissions cannot be removed without deterministic sufficiency evidence (e.g. unknown evidence forces escalation).",
    mitigation="Collect access logs, run simulations, or escalate to human operator.",
)

INVARIANT_NO_MUTATION_WITHOUT_SIMULATION = SecurityInvariant(
    id="NO_MUTATION_WITHOUT_SIMULATION",
    severity="high",
    category="verification",
    description="When counterfactual simulation is supported by provider, mutation cannot proceed without passing simulation.",
    mitigation="Run pre-commit simulation or escalate if provider does not support simulation.",
)

INVARIANT_NO_MUTATION_WITHOUT_PRE_APPLY_VERIFICATION = SecurityInvariant(
    id="NO_MUTATION_WITHOUT_PRE_APPLY_VERIFICATION",
    severity="critical",
    category="verification",
    description="Policy changes must pass all pre-apply validations and policy regression tests before mutation.",
    mitigation="Address failing pre-apply regression tests or syntax errors.",
)

INVARIANT_NO_COMPLETION_WITHOUT_VERIFICATION = SecurityInvariant(
    id="NO_COMPLETION_WITHOUT_VERIFICATION",
    severity="critical",
    category="verification",
    description="An autonomous remediation run cannot complete successfully without independent deterministic verification.",
    mitigation="Execute post-apply verification and confirm all operational and security invariants pass.",
)

INVARIANT_NO_UNAPPROVED_HIGH_RISK = SecurityInvariant(
    id="NO_UNAPPROVED_HIGH_RISK",
    severity="high",
    category="risk",
    description="Mutations classified as HIGH or CRITICAL risk or blast radius cannot be applied autonomously.",
    mitigation="Escalate for mandatory human approval before applying.",
)


class SecurityDecision(BaseModel):
    """Authoritative structured decision emitted by the Security Kernel."""

    allowed: bool = Field(default=False, description="True if policy mutation is approved to proceed")
    decision: GateDecision = Field(..., description="'allow', 'deny', or 'escalate'")
    reason: str = Field(default="", description="Summary explanation of decision")
    reason_codes: List[str] = Field(default_factory=list, description="Machine-readable code tags")
    risk_level: str = Field(default="low", description="Evaluated risk: 'low', 'medium', 'high', 'critical'")
    confidence: float = Field(default=1.0, description="Confidence score [0.0, 1.0]")
    blast_radius: str = Field(default="low", description="Evaluated blast radius: 'low', 'medium', 'high', 'critical'")
    violated_invariants: List[SecurityInvariant] = Field(
        default_factory=list, description="Invariants that were violated"
    )
    required_approval: bool = Field(default=False, description="Whether human approval is required")
    required_verification: List[str] = Field(
        default_factory=list, description="Verification checks required before or after application"
    )
    escalation_reason: Optional[str] = Field(
        default=None, description="Structured reason code if escalated"
    )
    details: Dict[str, Any] = Field(default_factory=dict, description="Diagnostic and forensic details")


# Alias for backward compatibility with Phase 2/3 SecurityGateResult
SecurityGateResult = SecurityDecision

__all__ = [
    "GateDecision",
    "SecurityInvariant",
    "SecurityDecision",
    "SecurityGateResult",
    "INVARIANT_NO_PRIVILEGE_EXPANSION",
    "INVARIANT_NO_PROTECTED_PERMISSION_MUTATION",
    "INVARIANT_NO_PROTECTED_RESOURCE_EXPOSURE",
    "INVARIANT_NO_CROSS_PROVIDER_MUTATION",
    "INVARIANT_NO_CROSS_TENANT_MUTATION",
    "INVARIANT_NO_STALE_STATE_MUTATION",
    "INVARIANT_NO_MUTATION_WITHOUT_EVIDENCE",
    "INVARIANT_NO_MUTATION_WITHOUT_SIMULATION",
    "INVARIANT_NO_MUTATION_WITHOUT_PRE_APPLY_VERIFICATION",
    "INVARIANT_NO_COMPLETION_WITHOUT_VERIFICATION",
    "INVARIANT_NO_UNAPPROVED_HIGH_RISK",
]

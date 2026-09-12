"""State models and comprehensive audit trail schemas."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.agent.planner import AgentPlan


class AuditEvent(BaseModel):
    """An immutable audit trail event with complete forensic traceability."""

    event_id: str = Field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:8]}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: str = Field(
        ...,
        description="e.g. 'observe', 'plan', 'decide', 'act', 'adapt', 'verify', 'escalate', 'rollback', 'complete', 'goal_received'",
    )
    relevant_ids: Dict[str, str] = Field(default_factory=dict)
    summary: str = Field(..., description="Human-readable event summary")
    details: Dict[str, Any] = Field(default_factory=dict)

    # Forensic audit metadata
    run_id: Optional[str] = None
    step_number: Optional[int] = None
    actor: str = Field(default="agent", description="Entity initiating event: 'agent', 'security_kernel', 'tool', 'verifier'")
    tool: Optional[str] = None
    arguments: Optional[Dict[str, Any]] = None
    result: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None
    confidence: Optional[float] = None
    evidence_refs: List[str] = Field(default_factory=list)


class AgentState(BaseModel):
    """Encapsulates the full state of an autonomous IAM agent run."""

    run_id: str = Field(default_factory=lambda: f"run-{uuid.uuid4().hex[:8]}")
    goal: str = Field(..., description="Primary security goal")
    current_phase: str = Field(default="INITIALIZING", description="Current lifecycle phase")
    current_role: Optional[str] = Field(default=None, description="Role under analysis")
    observed_evidence: Dict[str, Any] = Field(default_factory=dict)
    tool_calls: List[Dict[str, Any]] = Field(default_factory=list)
    tool_results: List[Dict[str, Any]] = Field(default_factory=list)
    candidate_policy_changes: List[Dict[str, Any]] = Field(default_factory=list)
    simulation_results: List[Dict[str, Any]] = Field(default_factory=list)
    failures: List[Dict[str, Any]] = Field(default_factory=list)
    replans: List[Dict[str, Any]] = Field(default_factory=list)
    verification_result: Optional[Dict[str, Any]] = Field(default=None)
    final_outcome: Optional[Dict[str, Any]] = Field(default=None)
    audit_trail: List[AuditEvent] = Field(default_factory=list)

    # Phase 2 additions
    current_plan: Optional[AgentPlan] = None
    decision_history: List[Dict[str, Any]] = Field(default_factory=list)
    policy_diff: Optional[Dict[str, Any]] = None
    policy_versions: List[Dict[str, Any]] = Field(default_factory=list)
    telemetry: Dict[str, Any] = Field(default_factory=dict)
    stop_reason: Optional[str] = None

    def record_event(
        self,
        event_type: str,
        summary: str,
        relevant_ids: Optional[Dict[str, str]] = None,
        details: Optional[Dict[str, Any]] = None,
        step_number: Optional[int] = None,
        actor: str = "agent",
        tool: Optional[str] = None,
        arguments: Optional[Dict[str, Any]] = None,
        result: Optional[Dict[str, Any]] = None,
        reason: Optional[str] = None,
        confidence: Optional[float] = None,
        evidence_refs: Optional[List[str]] = None,
    ) -> AuditEvent:
        """Helper to append an audit event to the state history."""
        event = AuditEvent(
            event_id=f"evt-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            relevant_ids=relevant_ids or {},
            summary=summary,
            details=details or {},
            run_id=self.run_id,
            step_number=step_number,
            actor=actor,
            tool=tool,
            arguments=arguments,
            result=result,
            reason=reason,
            confidence=confidence,
            evidence_refs=evidence_refs or [],
        )
        self.audit_trail.append(event)
        return event

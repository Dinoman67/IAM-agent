"""State models and audit trail schemas."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AuditEvent(BaseModel):
    """An immutable audit trail event."""

    event_id: str = Field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:8]}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: str = Field(..., description="e.g. 'goal_received', 'tool_called', 'simulation_failed'")
    relevant_ids: Dict[str, str] = Field(default_factory=dict)
    summary: str = Field(..., description="Human-readable event summary")
    details: Dict[str, Any] = Field(default_factory=dict)


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

    def record_event(
        self,
        event_type: str,
        summary: str,
        relevant_ids: Optional[Dict[str, str]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Helper to append an audit event to the state history."""
        event = AuditEvent(
            event_type=event_type,
            summary=summary,
            relevant_ids=relevant_ids or {},
            details=details or {},
        )
        self.audit_trail.append(event)
        return event

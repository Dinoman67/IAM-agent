"""Structured evidence model for least-privilege reasoning and verification."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EvidenceState(str, Enum):
    """Rigorous classification of permission necessity."""

    USED = "USED"                                       # Directly observed in telemetry/logs
    NOT_OBSERVED = "NOT_OBSERVED"                       # Absent in logs, but not yet proven safe to remove
    DEPENDENCY_REQUIRED = "DEPENDENCY_REQUIRED"         # Required via transitive or hidden architecture dependency
    PROVEN_UNNEEDED = "PROVEN_UNNEEDED"                 # Safe removal verified via counterfactual simulation
    UNKNOWN = "UNKNOWN"                                 # Insufficient data or inconclusive testing


class EvidenceStrength(str, Enum):
    """Reliability weight of the evidence source."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    PROVEN = "proven"


class EvidenceSource(str, Enum):
    ACCESS_LOGS = "access_logs"
    DEPENDENCY_GRAPH = "dependency_graph"
    SIMULATION = "simulation"
    WORKFLOW_TEST = "workflow_test"
    SECURITY_RULE = "security_rule"
    PROVIDER_CAPABILITY = "provider_capability"
    POLICY_ANALYSIS = "policy_analysis"


class Evidence(BaseModel):
    """Individual structured evidence artifact."""

    id: str = Field(default_factory=lambda: f"ev-{datetime.now(timezone.utc).strftime('%H%M%S%f')[:10]}")
    source: EvidenceSource = Field(..., description="Origin of the finding")
    permission: str = Field(..., description="Target permission action")
    claim: str = Field(..., description="Precise statement of what this evidence supports or refutes")
    strength: EvidenceStrength = Field(default=EvidenceStrength.MEDIUM)
    state: EvidenceState = Field(default=EvidenceState.UNKNOWN)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: Dict[str, Any] = Field(default_factory=dict)


class EvidenceBundle(BaseModel):
    """Aggregated evidence collection for a specific permission action."""

    permission: str
    items: List[Evidence] = Field(default_factory=list)
    state: EvidenceState = Field(default=EvidenceState.UNKNOWN)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    risk: str = Field(default="medium", description="Risk tier: 'low', 'medium', 'high', 'critical'")
    removal_permitted: bool = Field(default=False)
    justification: str = ""

    def add_evidence(self, item: Evidence) -> None:
        self.items.append(item)
        self._recompute_status()

    def _recompute_status(self) -> None:
        """Determines bundle state, confidence, and whether removal is permitted."""
        has_direct_use = any(e.state == EvidenceState.USED for e in self.items)
        has_dependency = any(e.state == EvidenceState.DEPENDENCY_REQUIRED for e in self.items)
        has_sim_pass = any(
            e.source == EvidenceSource.SIMULATION and e.details.get("simulation_passed", False)
            for e in self.items
        )
        has_sim_fail = any(
            e.source == EvidenceSource.SIMULATION and not e.details.get("simulation_passed", True)
            for e in self.items
        )

        if has_dependency:
            self.state = EvidenceState.DEPENDENCY_REQUIRED
            self.confidence = 0.98
            self.risk = "critical"
            self.removal_permitted = False
            self.justification = "Required by transitive service dependency; removal would break workflows."
        elif has_direct_use:
            self.state = EvidenceState.USED
            self.confidence = 0.95
            self.risk = "high"
            self.removal_permitted = False
            self.justification = "Observed in active access history."
        elif has_sim_fail:
            self.state = EvidenceState.DEPENDENCY_REQUIRED
            self.confidence = 0.92
            self.risk = "high"
            self.removal_permitted = False
            self.justification = "Simulation failed when permission was removed."
        elif has_sim_pass:
            self.state = EvidenceState.PROVEN_UNNEEDED
            self.confidence = 0.95
            self.risk = "low"
            self.removal_permitted = True
            self.justification = "Counterfactual simulation verified all workflows succeed without this action."
        else:
            # Unlogged but not yet tested counterfactually
            self.state = EvidenceState.NOT_OBSERVED
            self.confidence = 0.60
            self.risk = "medium"
            self.removal_permitted = False
            self.justification = "Action not observed in logs, but not yet verified as unneeded via simulation."

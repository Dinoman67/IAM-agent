"""Drift detection — continuous CIEM monitoring primitive.

Compares a recorded baseline against live/current permissions and flags:
added grants, removed grants, version jumps (out-of-band changes), and
never-seen-before admin escalations. Stateless pure function; the
background scheduler lives outside (cron/EventBridge calls the API).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

ADMIN_MARKERS = ("iam:", "organizations:", "sts:AssumeRole", "*")


class DriftReport(BaseModel):
    role_id: str
    drifted: bool = False
    added: List[str] = Field(default_factory=list)
    removed: List[str] = Field(default_factory=list)
    version_jump: Optional[str] = None
    escalations: List[str] = Field(default_factory=list)
    severity: str = "NONE"  # NONE | LOW | MEDIUM | HIGH | CRITICAL
    recommendation: str = "No drift detected."


def check_drift(
    role_id: str,
    baseline_permissions: List[str],
    current_permissions: List[str],
    baseline_version: Optional[str] = None,
    current_version: Optional[str] = None,
) -> DriftReport:
    base, cur = set(baseline_permissions), set(current_permissions)
    added = sorted(cur - base)
    removed = sorted(base - cur)
    escalations = [p for p in added if "*" in p or p.startswith(ADMIN_MARKERS)]
    jump = None
    if baseline_version and current_version and baseline_version != current_version:
        jump = f"{baseline_version} -> {current_version} (possible out-of-band change)"
    drifted = bool(added or removed or jump)
    if escalations:
        severity = "CRITICAL"
        rec = f"Admin/wildcard grants appeared out-of-band: {escalations}. Re-run remediation immediately."
    elif added and jump:
        severity = "HIGH"
        rec = "Permissions changed outside the agent. Refresh baseline and replan."
    elif added or removed:
        severity = "MEDIUM"
        rec = "Permission drift detected. Review and re-verify workflows."
    elif jump:
        severity = "LOW"
        rec = "Version moved without permission change. Confirm author."
    else:
        severity, rec = "NONE", "No drift detected."
    return DriftReport(
        role_id=role_id,
        drifted=drifted,
        added=added,
        removed=removed,
        version_jump=jump,
        escalations=escalations,
        severity=severity,
        recommendation=rec,
    )


__all__ = ["DriftReport", "check_drift"]

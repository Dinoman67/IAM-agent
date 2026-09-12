"""Temporal mining — distinguish RARE_BUT_CRITICAL from truly DEAD permissions.

Core thesis: NOT_OBSERVED (30d) != PROVEN_UNNEEDED (annual DR, quarterly jobs).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

from backend.environment.loader import IAMEnvironment

TemporalClass = Literal["FREQUENT", "RARE_BUT_CRITICAL", "SEASONAL_CANDIDATE", "DEAD"]
Recommendation = Literal["RETAIN", "REVIEW", "REMOVE"]


class TemporalFinding(BaseModel):
    permission: str
    uses_30d: int = 0
    uses_365d: int = 0
    days_since_last_use: Optional[int] = None
    dependency_linked: bool = False
    classification: TemporalClass = "DEAD"
    recommendation: Recommendation = "REMOVE"
    confidence: float = 0.0
    reason: str = ""


class TemporalReport(BaseModel):
    role_id: str
    window_days: int = 365
    findings: List[TemporalFinding] = Field(default_factory=list)
    retain: List[str] = Field(default_factory=list)
    review: List[str] = Field(default_factory=list)
    remove: List[str] = Field(default_factory=list)


def _parse_ts(ts: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def classify_permissions(
    role_id: str, env: IAMEnvironment, window_days: int = 365, now: Optional[datetime] = None
) -> TemporalReport:
    role = env.get_role(role_id)
    if not role:
        raise ValueError(f"Role '{role_id}' not found.")
    now = now or datetime.now(timezone.utc)
    active = role.active_permissions()
    logs = env.get_access_history(role_id=role_id)
    dep_perms = {d.required_permission for d in env.data.dependencies}

    findings: List[TemporalFinding] = []
    for perm in active:
        uses = [lg for lg in logs if lg.action == perm and lg.success]
        # window filter
        in_window = []
        last: Optional[datetime] = None
        for lg in uses:
            ts = _parse_ts(lg.timestamp)
            if ts is None:
                continue
            age_days = (now - ts).days
            if 0 <= age_days <= window_days:
                in_window.append(lg)
                if last is None or ts > last:
                    last = ts
        uses_365 = len(in_window)
        uses_30 = sum(1 for lg in in_window if (now - _parse_ts(lg.timestamp)).days <= 30) if in_window else 0
        days_since = (now - last).days if last else None
        linked = perm in dep_perms

        if uses_30 >= 5:
            cls: TemporalClass = "FREQUENT"
            rec: Recommendation = "RETAIN"
            conf, reason = 0.98, "Hot path: frequent use in last 30d."
        elif linked:
            # Even with zero logs, dependency-linked (e.g. kms:Decrypt via SSE-KMS) must be retained
            cls, rec = "RARE_BUT_CRITICAL", "RETAIN"
            conf = 0.93 if uses_365 == 0 else 0.88
            reason = "Transitive dependency (e.g. S3 SSE-KMS) requires it despite rare/no direct logs."
        elif uses_365 == 0:
            cls, rec = "DEAD", "REMOVE"
            conf, reason = 0.90, "No successful use in full window and no dependency link."
        elif days_since is not None and days_since > 90:
            cls, rec = "SEASONAL_CANDIDATE", "REVIEW"
            conf, reason = 0.72, f"Last seen {days_since}d ago — possible seasonal/DR job; needs human review, do not auto-remove."
        else:
            cls, rec = "RARE_BUT_CRITICAL", "RETAIN"
            conf, reason = 0.65, "Rarely used but within window — retain pending more evidence."

        findings.append(
            TemporalFinding(
                permission=perm,
                uses_30d=uses_30,
                uses_365d=uses_365,
                days_since_last_use=days_since,
                dependency_linked=linked,
                classification=cls,
                recommendation=rec,
                confidence=conf,
                reason=reason,
            )
        )

    return TemporalReport(
        role_id=role_id,
        window_days=window_days,
        findings=findings,
        retain=[f.permission for f in findings if f.recommendation == "RETAIN"],
        review=[f.permission for f in findings if f.recommendation == "REVIEW"],
        remove=[f.permission for f in findings if f.recommendation == "REMOVE"],
    )


__all__ = ["TemporalFinding", "TemporalReport", "classify_permissions"]

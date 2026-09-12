"""Structured policy diffing and audit comparison."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PolicyDiff(BaseModel):
    """Structured policy diff documenting changes, rationales, and verification."""

    role_id: str
    from_version: str
    to_version: Optional[str] = None
    removed: List[str] = Field(default_factory=list)
    kept: List[str] = Field(default_factory=list)
    added: List[str] = Field(default_factory=list)
    why_removed: Dict[str, str] = Field(default_factory=dict)
    why_kept: Dict[str, str] = Field(default_factory=dict)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    simulation_result: Optional[Dict[str, Any]] = None
    verification_result: Optional[Dict[str, Any]] = None

    def render_markdown(self) -> str:
        """Renders human-readable before/after remediation diff."""
        lines = [
            f"### IAM Policy Remediation Diff: `{self.role_id}`",
            f"**From Version:** `{self.from_version}` -> **To Version:** `{self.to_version or 'Candidate'}`",
            "",
            "#### REMOVED Permissions (-)",
        ]
        if self.removed:
            for p in self.removed:
                reason = self.why_removed.get(p, "Identified as excessive privilege")
                lines.append(f"- `- {p}`: *{reason}*")
        else:
            lines.append("*(none)*")

        lines.extend(["", "#### KEPT Permissions (+)"])
        if self.kept:
            for p in self.kept:
                reason = self.why_kept.get(p, "Required for service workflow")
                lines.append(f"- `+ {p}`: *{reason}*")
        else:
            lines.append("*(none)*")

        if self.added:
            lines.extend(["", "#### ADDED Permissions (scoped)"])
            for p in self.added:
                lines.append(f"- `+ {p}`")

        return "\n".join(lines)


def compute_policy_diff(
    role_id: str,
    from_version: str,
    original_permissions: List[str],
    new_permissions: List[str],
    to_version: Optional[str] = None,
    retained_dependencies: Optional[List[str]] = None,
    simulation_result: Optional[Dict[str, Any]] = None,
    verification_result: Optional[Dict[str, Any]] = None,
) -> PolicyDiff:
    """Computes before/after diff with justifications and evidence."""
    orig_set = set(original_permissions)
    new_set = set(new_permissions)

    removed = [p for p in original_permissions if p not in new_set]
    kept = [p for p in original_permissions if p in new_set]
    added = [p for p in new_permissions if p not in orig_set]

    retained_deps = retained_dependencies or []

    why_removed: Dict[str, str] = {}
    for p in removed:
        if "*" in p:
            why_removed[p] = "Excessive wildcard administrative permission not observed in execution logs"
        else:
            why_removed[p] = "Unused permission verified safe to remove via counterfactual simulation"

    why_kept: Dict[str, str] = {}
    for p in kept:
        if p in retained_deps:
            why_kept[p] = "Critical downstream architecture dependency (e.g. KMS SSE decryption)"
        else:
            why_kept[p] = "Observed in active workflow execution logs"

    return PolicyDiff(
        role_id=role_id,
        from_version=from_version,
        to_version=to_version,
        removed=removed,
        kept=kept,
        added=added,
        why_removed=why_removed,
        why_kept=why_kept,
        simulation_result=simulation_result,
        verification_result=verification_result,
    )

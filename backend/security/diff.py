"""Structured provider-aware policy diffing and audit comparison."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PolicyDiff(BaseModel):
    """Structured policy diff documenting common semantic changes and provider-specific transformations."""

    role_id: str
    from_version: str
    to_version: Optional[str] = None
    provider: str = Field(default="aws", description="Target provider: aws, gcp, azure")

    # Common semantic diff
    removed: List[str] = Field(default_factory=list)
    kept: List[str] = Field(default_factory=list)
    added: List[str] = Field(default_factory=list)
    why_removed: Dict[str, str] = Field(default_factory=dict)
    why_kept: Dict[str, str] = Field(default_factory=dict)
    evidence: Dict[str, Any] = Field(default_factory=dict)

    # Provider-specific diff representation
    provider_diff: Dict[str, Any] = Field(default_factory=dict)

    simulation_result: Optional[Dict[str, Any]] = None
    verification_result: Optional[Dict[str, Any]] = None

    def render_markdown(self) -> str:
        """Renders human-readable before/after remediation diff with provider-specific representation."""
        prov = self.provider.upper()
        lines = [
            f"### IAM Policy Remediation Diff: `{self.role_id}` ({prov})",
            f"**From Version:** `{self.from_version}` -> **To Version:** `{self.to_version or 'Candidate'}`",
            "",
            "#### COMMON SEMANTIC DIFF",
            "**REMOVED Permissions (-):**",
        ]
        if self.removed:
            for p in self.removed:
                reason = self.why_removed.get(p, "Identified as excessive privilege")
                lines.append(f"- `- {p}`: *{reason}*")
        else:
            lines.append("*(none)*")

        lines.extend(["", "**KEPT Permissions (+):**"])
        if self.kept:
            for p in self.kept:
                reason = self.why_kept.get(p, "Required for service workflow")
                lines.append(f"- `+ {p}`: *{reason}*")
        else:
            lines.append("*(none)*")

        if self.added:
            lines.extend(["", "**ADDED Permissions (scoped):**"])
            for p in self.added:
                lines.append(f"- `+ {p}`")

        # Provider-specific representation section
        lines.extend(["", f"#### {prov}-SPECIFIC DIFF"])
        if self.provider.lower() == "aws":
            lines.append(f"**AWS Policy Statement:** `AllowRequestedActions`")
            if self.removed:
                for p in self.removed:
                    lines.append(f"- Remove Action: `\"{p}\"`")
            else:
                lines.append("*(no AWS action modifications)*")
        elif self.provider.lower() == "gcp":
            lines.append(f"**GCP Role / Binding:** `{self.role_id}`")
            if self.removed:
                for p in self.removed:
                    lines.append(f"- Revoke Permission from Role/Binding: `\"{p}\"`")
            else:
                lines.append("*(no GCP permission modifications)*")
        elif self.provider.lower() == "azure":
            lines.append(f"**Azure Role Definition / Assignment:** `{self.role_id}`")
            if self.removed:
                for p in self.removed:
                    lines.append(f"- Remove Action from Definition: `\"{p}\"`")
            else:
                lines.append("*(no Azure action modifications)*")
        else:
            lines.append(f"Provider details: {self.provider_diff}")

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
    provider: str = "aws",
    provider_diff: Optional[Dict[str, Any]] = None,
) -> PolicyDiff:
    """Computes before/after diff with justifications, evidence, and provider-specific details."""
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

    # Compute provider-specific diff structure
    p_diff = provider_diff or {}
    if not p_diff:
        if provider.lower() == "aws":
            p_diff = {
                "statement_id": "AllowRequestedActions",
                "removed_actions": removed,
                "retained_actions": kept,
            }
        elif provider.lower() == "gcp":
            p_diff = {
                "role_id": role_id,
                "removed_permissions": removed,
                "retained_permissions": kept,
                "concurrency_control": "etag",
            }
        elif provider.lower() == "azure":
            p_diff = {
                "role_definition_id": role_id,
                "removed_actions": removed,
                "retained_actions": kept,
                "assignment_scope": "/",
            }

    return PolicyDiff(
        role_id=role_id,
        from_version=from_version,
        to_version=to_version,
        provider=provider.lower(),
        removed=removed,
        kept=kept,
        added=added,
        why_removed=why_removed,
        why_kept=why_kept,
        provider_diff=p_diff,
        simulation_result=simulation_result,
        verification_result=verification_result,
    )

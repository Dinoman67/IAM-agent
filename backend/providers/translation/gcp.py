"""Google Cloud Platform (GCP) IAM policy and role translation to and from Common IAM IR."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from backend.models.iam import (
    CommonAction,
    CommonBinding,
    CommonCondition,
    CommonPolicy,
    CommonPrincipal,
    CommonResource,
    CommonStatement,
    PolicyEffect,
)
from backend.providers.common.errors import ProviderMismatchError, enforce_provider_match


def gcp_role_to_ir(role_dict: Dict[str, Any]) -> CommonPolicy:
    """Translates a GCP IAM Role definition into Common IAM IR."""
    if not isinstance(role_dict, dict):
        raise ValueError(f"Malformed GCP role: expected dict, got {type(role_dict)}")

    # Provider mismatch protection
    if "Statement" in role_dict or "Version" in role_dict:
        raise ProviderMismatchError(
            source_provider="aws",
            target_provider="gcp",
            reason="Detected AWS IAM Statement/Version passed to GCP role translator.",
            recommended_action="Use aws_policy_to_ir instead.",
        )

    role_name = role_dict.get("name", "roles/customRole")
    title = role_dict.get("title", role_name.split("/")[-1])
    perms = role_dict.get("includedPermissions", [])

    actions = [CommonAction.from_string(p, provider="gcp") for p in perms]
    stmt = CommonStatement(
        sid="RolePermissions",
        effect=PolicyEffect.ALLOW,
        actions=actions,
        resources=[CommonResource(arn_or_id="*")],
        provider_metadata={"stage": role_dict.get("stage", "GA")},
    )

    return CommonPolicy(
        id=role_name,
        name=title,
        provider="gcp",
        version=role_dict.get("etag", "etag-1"),
        statements=[stmt],
        provider_metadata={
            "description": role_dict.get("description", ""),
            "stage": role_dict.get("stage", "GA"),
            "etag": role_dict.get("etag", ""),
        },
    )


def ir_to_gcp_role(common_policy: CommonPolicy) -> Dict[str, Any]:
    """Translates Common IAM IR policy into a GCP IAM Role dictionary."""
    enforce_provider_match("gcp", common_policy.provider, context="GCP role export")

    perms = common_policy.extract_permission_strings()
    return {
        "name": common_policy.id,
        "title": common_policy.name,
        "description": common_policy.provider_metadata.get("description", ""),
        "includedPermissions": perms,
        "stage": common_policy.provider_metadata.get("stage", "GA"),
        "etag": common_policy.version,
    }


def gcp_binding_to_ir(binding_dict: Dict[str, Any], scope: Optional[str] = None) -> List[CommonBinding]:
    """Translates a GCP IAM Policy Binding into one or more CommonBinding records."""
    role = binding_dict.get("role", "")
    members = binding_dict.get("members", [])
    raw_cond = binding_dict.get("condition")

    condition: Optional[CommonCondition] = None
    if raw_cond and isinstance(raw_cond, dict):
        condition = CommonCondition(
            operator="CEL",
            key=raw_cond.get("title", "expression"),
            values=[raw_cond.get("expression", "")],
            provider_metadata=raw_cond,
        )

    bindings: List[CommonBinding] = []
    for m in members:
        bindings.append(
            CommonBinding(
                principal_id=m,
                role_or_policy_id=role,
                scope=scope,
                condition=condition,
                provider="gcp",
                provider_metadata={"original_binding": binding_dict},
            )
        )
    return bindings


def ir_to_gcp_binding(common_bindings: List[CommonBinding]) -> List[Dict[str, Any]]:
    """Groups CommonBinding records by role into standard GCP IAM binding structures."""
    grouped: Dict[str, Dict[str, Any]] = {}

    for b in common_bindings:
        enforce_provider_match("gcp", b.provider, context="GCP binding export")
        role = b.role_or_policy_id
        if role not in grouped:
            entry: Dict[str, Any] = {"role": role, "members": []}
            if b.condition:
                entry["condition"] = {
                    "title": b.condition.key,
                    "expression": b.condition.values[0] if b.condition.values else "",
                }
            grouped[role] = entry

        if b.principal_id not in grouped[role]["members"]:
            grouped[role]["members"].append(b.principal_id)

    return list(grouped.values())


def gcp_policy_to_ir(policy_dict: Dict[str, Any], scope: Optional[str] = None) -> CommonPolicy:
    """Translates a full GCP IAM Policy (bindings, etag, version) into CommonPolicy."""
    if not isinstance(policy_dict, dict):
        raise ValueError(f"Malformed GCP policy: expected dict, got {type(policy_dict)}")

    if "Statement" in policy_dict:
        raise ProviderMismatchError(
            source_provider="aws",
            target_provider="gcp",
            reason="Detected AWS Statement block passed to GCP policy translator.",
            recommended_action="Use aws_policy_to_ir instead.",
        )

    bindings_list: List[CommonBinding] = []
    for b in policy_dict.get("bindings", []):
        bindings_list.extend(gcp_binding_to_ir(b, scope=scope))

    return CommonPolicy(
        id=scope or "projects/gcp-default-project",
        name=f"IAMPolicy-{scope or 'default'}",
        provider="gcp",
        version=str(policy_dict.get("etag", policy_dict.get("version", "1"))),
        bindings=bindings_list,
        provider_metadata={
            "etag": policy_dict.get("etag", ""),
            "version": policy_dict.get("version", 1),
        },
    )


def ir_to_gcp_policy(common_policy: CommonPolicy) -> Dict[str, Any]:
    """Translates CommonPolicy containing bindings into GCP IAM Policy dictionary."""
    enforce_provider_match("gcp", common_policy.provider, context="GCP policy export")
    bindings = ir_to_gcp_binding(common_policy.bindings)
    return {
        "bindings": bindings,
        "etag": common_policy.provider_metadata.get("etag", common_policy.version),
        "version": common_policy.provider_metadata.get("version", 1),
    }


__all__ = [
    "gcp_role_to_ir",
    "ir_to_gcp_role",
    "gcp_binding_to_ir",
    "ir_to_gcp_binding",
    "gcp_policy_to_ir",
    "ir_to_gcp_policy",
]

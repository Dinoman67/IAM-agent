"""Microsoft Azure RBAC policy, role definition, and role assignment translation to and from Common IAM IR."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from backend.models.iam import (
    CommonAction,
    CommonBinding,
    CommonCondition,
    CommonPolicy,
    CommonResource,
    CommonStatement,
    PolicyEffect,
)
from backend.providers.common.errors import ProviderMismatchError, enforce_provider_match


def azure_role_def_to_ir(role_def_dict: Dict[str, Any]) -> CommonPolicy:
    """Translates an Azure RBAC Role Definition dictionary into Common IAM IR."""
    if not isinstance(role_def_dict, dict):
        raise ValueError(f"Malformed Azure role definition: expected dict, got {type(role_def_dict)}")

    # Provider mismatch protection
    if "Statement" in role_def_dict or "Version" in role_def_dict:
        raise ProviderMismatchError(
            source_provider="aws",
            target_provider="azure",
            reason="Detected AWS Statement/Version passed to Azure role definition translator.",
            recommended_action="Use aws_policy_to_ir instead.",
        )

    role_id = role_def_dict.get("id", "/providers/Microsoft.Authorization/roleDefinitions/custom")
    props = role_def_dict.get("properties", role_def_dict)
    role_name = props.get("roleName", role_id.split("/")[-1])
    assignable_scopes = props.get("assignableScopes", ["/"])

    statements: List[CommonStatement] = []
    for perm_block in props.get("permissions", []):
        allow_actions = [
            CommonAction.from_string(a, provider="azure")
            for a in (perm_block.get("actions", []) + perm_block.get("dataActions", []))
        ]
        if allow_actions:
            statements.append(
                CommonStatement(
                    sid="AllowedActions",
                    effect=PolicyEffect.ALLOW,
                    actions=allow_actions,
                    resources=[CommonResource(arn_or_id=s, scope=s) for s in assignable_scopes],
                )
            )

        not_actions = [
            CommonAction.from_string(na, provider="azure")
            for na in (perm_block.get("notActions", []) + perm_block.get("notDataActions", []))
        ]
        if not_actions:
            statements.append(
                CommonStatement(
                    sid="NotActions",
                    effect=PolicyEffect.DENY,
                    actions=not_actions,
                    resources=[CommonResource(arn_or_id=s, scope=s) for s in assignable_scopes],
                )
            )

    return CommonPolicy(
        id=role_id,
        name=role_name,
        provider="azure",
        version="1.0",
        statements=statements,
        provider_metadata={
            "description": props.get("description", ""),
            "assignableScopes": assignable_scopes,
            "roleType": props.get("type", "CustomRole"),
        },
    )


def ir_to_azure_role_def(common_policy: CommonPolicy) -> Dict[str, Any]:
    """Translates Common IAM IR policy into an Azure RBAC Role Definition dictionary."""
    enforce_provider_match("azure", common_policy.provider, context="Azure role definition export")

    actions: List[str] = []
    not_actions: List[str] = []

    for stmt in common_policy.statements:
        if stmt.effect == PolicyEffect.ALLOW:
            for a in stmt.actions:
                actions.append(a.raw_action)
        elif stmt.effect == PolicyEffect.DENY:
            for a in stmt.actions:
                not_actions.append(a.raw_action)

    assignable_scopes = common_policy.provider_metadata.get("assignableScopes", ["/"])

    return {
        "id": common_policy.id,
        "name": common_policy.id.split("/")[-1],
        "properties": {
            "roleName": common_policy.name,
            "description": common_policy.provider_metadata.get("description", ""),
            "type": common_policy.provider_metadata.get("roleType", "CustomRole"),
            "permissions": [
                {
                    "actions": actions,
                    "notActions": not_actions,
                    "dataActions": [],
                    "notDataActions": [],
                }
            ],
            "assignableScopes": assignable_scopes,
        },
    }


def azure_assignment_to_ir(assignment_dict: Dict[str, Any]) -> CommonBinding:
    """Translates an Azure RBAC Role Assignment dictionary into CommonBinding."""
    if not isinstance(assignment_dict, dict):
        raise ValueError(f"Malformed Azure role assignment: expected dict, got {type(assignment_dict)}")

    # Provider mismatch protection
    if "Statement" in assignment_dict:
        raise ProviderMismatchError(
            source_provider="aws",
            target_provider="azure",
            reason="Detected AWS Statement block passed to Azure assignment translator.",
            recommended_action="Use aws_policy_to_ir instead.",
        )

    props = assignment_dict.get("properties", assignment_dict)
    principal_id = props.get("principalId", "")
    role_def_id = props.get("roleDefinitionId", "")
    scope = props.get("scope", "")
    condition_str = props.get("condition")

    cond = None
    if condition_str:
        cond = CommonCondition(operator="AzureCondition", key="condition", values=[condition_str])

    return CommonBinding(
        principal_id=principal_id,
        role_or_policy_id=role_def_id,
        scope=scope,
        condition=cond,
        provider="azure",
        provider_metadata={"assignment_id": assignment_dict.get("id", "")},
    )


def ir_to_azure_assignment(common_binding: CommonBinding) -> Dict[str, Any]:
    """Translates a CommonBinding into an Azure RBAC Role Assignment dictionary."""
    enforce_provider_match("azure", common_binding.provider, context="Azure role assignment export")

    assignment_id = common_binding.provider_metadata.get(
        "assignment_id", f"{common_binding.scope or ''}/providers/Microsoft.Authorization/roleAssignments/guid"
    )
    result: Dict[str, Any] = {
        "id": assignment_id,
        "properties": {
            "roleDefinitionId": common_binding.role_or_policy_id,
            "principalId": common_binding.principal_id,
            "scope": common_binding.scope or "/",
        },
    }
    if common_binding.condition and common_binding.condition.values:
        result["properties"]["condition"] = common_binding.condition.values[0]

    return result


__all__ = [
    "azure_role_def_to_ir",
    "ir_to_azure_role_def",
    "azure_assignment_to_ir",
    "ir_to_azure_assignment",
]

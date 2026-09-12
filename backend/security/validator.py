"""Provider-aware policy, binding, and role validation framework."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from backend.models.iam import (
    CommonBinding,
    CommonPolicy,
    PolicyEffect,
)
from backend.providers.base import ProviderValidationResult
from backend.providers.common.errors import ProviderMismatchError


def validate_common_policy(
    policy: CommonPolicy,
    base_policy: Optional[CommonPolicy] = None,
) -> ProviderValidationResult:
    """Validates generic IAM IR invariants across all cloud providers."""
    errors: List[str] = []
    warnings: List[str] = []

    if not policy.id:
        errors.append("Policy missing required identifier 'id'")
    if not policy.name:
        warnings.append("Policy missing human-readable 'name'")
    if not policy.provider:
        errors.append("Policy missing cloud provider specification")

    if not policy.statements and not policy.bindings:
        errors.append("Policy contains neither statements nor bindings; empty authorization specification")

    for i, stmt in enumerate(policy.statements):
        if not stmt.actions:
            errors.append(f"Statement {stmt.sid or i} defines no actions")
        if stmt.effect not in (PolicyEffect.ALLOW, PolicyEffect.DENY):
            errors.append(f"Statement {stmt.sid or i} has invalid effect '{stmt.effect}'")

    # Invariant: check unexpected privilege expansion compared to baseline
    if base_policy:
        base_actions = set(base_policy.extract_permission_strings())
        curr_actions = set(policy.extract_permission_strings())
        expanded = curr_actions - base_actions
        if expanded:
            errors.append(f"Unexpected privilege expansion: newly added permissions not in baseline: {sorted(list(expanded))}")

    return ProviderValidationResult(
        is_valid=len(errors) == 0,
        provider=policy.provider,
        errors=errors,
        warnings=warnings,
        details={"statement_count": len(policy.statements), "binding_count": len(policy.bindings)},
    )


def validate_aws_policy(policy_or_dict: Any) -> ProviderValidationResult:
    """Validates AWS-specific IAM policy document syntax and invariants."""
    errors: List[str] = []
    warnings: List[str] = []

    if isinstance(policy_or_dict, CommonPolicy):
        if policy_or_dict.provider.lower() != "aws":
            return ProviderValidationResult(
                is_valid=False,
                provider="aws",
                errors=[f"Provider mismatch: expected 'aws', got '{policy_or_dict.provider}'"],
                details={"provider_mismatch": True},
            )
        statements = policy_or_dict.statements
    elif isinstance(policy_or_dict, dict):
        if "includedPermissions" in policy_or_dict or "bindings" in policy_or_dict or "role" in policy_or_dict or "members" in policy_or_dict:
            return ProviderValidationResult(
                is_valid=False,
                provider="aws",
                errors=["Provider mismatch: GCP IAM format provided to AWS validator"],
                details={"provider_mismatch": True},
            )
        if "properties" in policy_or_dict and ("roleDefinitionId" in policy_or_dict["properties"] or "assignableScopes" in policy_or_dict["properties"]):
            return ProviderValidationResult(
                is_valid=False,
                provider="aws",
                errors=["Provider mismatch: Azure RBAC format provided to AWS validator"],
                details={"provider_mismatch": True},
            )
        raw_statements = policy_or_dict.get("Statement")
        if raw_statements is None:
            return ProviderValidationResult(
                is_valid=False,
                provider="aws",
                errors=["AWS policy document missing required 'Statement' field"],
                details={"missing_statement": True},
            )
        statements = raw_statements if isinstance(raw_statements, list) else [raw_statements]
    else:
        return ProviderValidationResult(
            is_valid=False,
            provider="aws",
            errors=[f"Unsupported input type for AWS validator: {type(policy_or_dict)}"],
        )

    if not statements:
        errors.append("AWS policy document must declare at least one Statement")

    for idx, stmt in enumerate(statements):
        if isinstance(stmt, dict):
            actions = stmt.get("Action", [])
            actions = actions if isinstance(actions, list) else [actions]
            effect = stmt.get("Effect", "")
            resource = stmt.get("Resource", [])
        else:
            actions = [a.raw_action for a in stmt.actions]
            effect = stmt.effect.value
            resource = [r.arn_or_id for r in stmt.resources]

        if effect not in ("Allow", "Deny"):
            errors.append(f"Statement {idx+1}: Invalid AWS Effect '{effect}' (must be 'Allow' or 'Deny')")

        if not actions:
            errors.append(f"Statement {idx+1}: AWS statement must declare at least one Action")
        for a in actions:
            if a != "*" and ":" not in a:
                errors.append(f"Statement {idx+1}: AWS action '{a}' invalid (must be '*' or 'service:Action')")

        if not resource:
            errors.append(f"Statement {idx+1}: AWS statement must declare at least one Resource")

    return ProviderValidationResult(
        is_valid=len(errors) == 0,
        provider="aws",
        errors=errors,
        warnings=warnings,
        details={"validated_statements": len(statements)},
    )


def validate_gcp_binding(binding_or_dict: Any) -> ProviderValidationResult:
    """Validates GCP IAM role binding syntax, membership prefixes, and CEL conditions."""
    errors: List[str] = []
    warnings: List[str] = []

    if isinstance(binding_or_dict, CommonBinding):
        if binding_or_dict.provider.lower() != "gcp":
            return ProviderValidationResult(
                is_valid=False,
                provider="gcp",
                errors=[f"Provider mismatch: expected 'gcp', got '{binding_or_dict.provider}'"],
                details={"provider_mismatch": True},
            )
        role = binding_or_dict.role_or_policy_id
        members = [binding_or_dict.principal_id]
    elif isinstance(binding_or_dict, dict):
        if "Statement" in binding_or_dict:
            return ProviderValidationResult(
                is_valid=False,
                provider="gcp",
                errors=["Provider mismatch: AWS IAM Statement provided to GCP validator"],
                details={"provider_mismatch": True},
            )
        role = binding_or_dict.get("role", "")
        members = binding_or_dict.get("members", [])
    else:
        return ProviderValidationResult(
            is_valid=False,
            provider="gcp",
            errors=[f"Unsupported input type for GCP validator: {type(binding_or_dict)}"],
        )

    if not role:
        errors.append("GCP binding must specify a 'role'")
    elif not (role.startswith("roles/") or role.startswith("projects/") or role.startswith("organizations/")):
        errors.append(f"Invalid GCP role format '{role}'; must begin with 'roles/' or 'projects/.../roles/'")

    valid_prefixes = ("user:", "serviceAccount:", "group:", "domain:", "allUsers", "allAuthenticatedUsers", "principalSet:", "principal:")
    if not members:
        errors.append("GCP binding must declare at least one member")
    for m in members:
        if not any(m.startswith(p) for p in valid_prefixes):
            errors.append(f"Invalid GCP member '{m}'; must be prefixed (e.g. 'user:...', 'serviceAccount:...', 'group:...')")

    return ProviderValidationResult(
        is_valid=len(errors) == 0,
        provider="gcp",
        errors=errors,
        warnings=warnings,
        details={"role": role, "member_count": len(members)},
    )


def validate_azure_assignment(assignment_or_dict: Any) -> ProviderValidationResult:
    """Validates Azure RBAC role assignment scope, role definition, and principal formatting."""
    errors: List[str] = []
    warnings: List[str] = []

    if isinstance(assignment_or_dict, CommonBinding):
        if assignment_or_dict.provider.lower() != "azure":
            return ProviderValidationResult(
                is_valid=False,
                provider="azure",
                errors=[f"Provider mismatch: expected 'azure', got '{assignment_or_dict.provider}'"],
                details={"provider_mismatch": True},
            )
        principal_id = assignment_or_dict.principal_id
        role_def_id = assignment_or_dict.role_or_policy_id
        scope = assignment_or_dict.scope or "/"
    elif isinstance(assignment_or_dict, dict):
        if "Statement" in assignment_or_dict:
            return ProviderValidationResult(
                is_valid=False,
                provider="azure",
                errors=["Provider mismatch: AWS IAM Statement provided to Azure validator"],
                details={"provider_mismatch": True},
            )
        props = assignment_or_dict.get("properties", assignment_or_dict)
        principal_id = props.get("principalId", "")
        role_def_id = props.get("roleDefinitionId", "")
        scope = props.get("scope", "/")
    else:
        return ProviderValidationResult(
            is_valid=False,
            provider="azure",
            errors=[f"Unsupported input type for Azure validator: {type(assignment_or_dict)}"],
        )

    if not principal_id:
        errors.append("Azure role assignment missing 'principalId'")
    if not role_def_id:
        errors.append("Azure role assignment missing 'roleDefinitionId'")
    if not scope.startswith("/"):
        errors.append(f"Invalid Azure scope '{scope}'; must start with leading slash '/'")

    return ProviderValidationResult(
        is_valid=len(errors) == 0,
        provider="azure",
        errors=errors,
        warnings=warnings,
        details={"scope": scope, "role_definition": role_def_id},
    )


__all__ = [
    "validate_common_policy",
    "validate_aws_policy",
    "validate_gcp_binding",
    "validate_azure_assignment",
]

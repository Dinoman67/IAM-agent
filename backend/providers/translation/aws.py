"""AWS IAM Policy translation to and from Common IAM IR."""

from __future__ import annotations

from typing import Any, Dict, List, Union
from backend.models.iam import (
    CommonAction,
    CommonCondition,
    CommonPolicy,
    CommonPrincipal,
    CommonResource,
    CommonStatement,
    PolicyEffect,
)
from backend.providers.common.errors import ProviderMismatchError, enforce_provider_match


def aws_policy_to_ir(policy_dict: Dict[str, Any], policy_id: str = "aws-policy", name: str = "AwsPolicy") -> CommonPolicy:
    """Translates an AWS IAM policy JSON dictionary into Common IAM IR."""
    if not isinstance(policy_dict, dict):
        raise ValueError(f"Malformed AWS policy: expected dictionary, got {type(policy_dict)}")

    # Provider mismatch check: detect if clearly GCP or Azure
    if "includedPermissions" in policy_dict or "bindings" in policy_dict:
        raise ProviderMismatchError(
            source_provider="gcp",
            target_provider="aws",
            reason="Detected GCP IAM policy schema (bindings/includedPermissions) passed to AWS translator.",
            recommended_action="Use gcp_policy_to_ir or gcp_role_to_ir instead.",
        )
    if "properties" in policy_dict and ("roleDefinitionId" in policy_dict["properties"] or "assignableScopes" in policy_dict["properties"]):
        raise ProviderMismatchError(
            source_provider="azure",
            target_provider="aws",
            reason="Detected Azure RBAC schema (properties.roleDefinitionId) passed to AWS translator.",
            recommended_action="Use azure_role_def_to_ir or azure_assignment_to_ir instead.",
        )

    version = str(policy_dict.get("Version", "2012-10-17"))
    raw_statements = policy_dict.get("Statement", [])
    if isinstance(raw_statements, dict):
        raw_statements = [raw_statements]

    ir_statements: List[CommonStatement] = []

    for idx, raw_stmt in enumerate(raw_statements):
        sid = raw_stmt.get("Sid", f"Stmt{idx+1}")
        effect_str = raw_stmt.get("Effect", "Allow")
        effect = PolicyEffect.ALLOW if effect_str.lower() == "allow" else PolicyEffect.DENY

        # Actions
        raw_actions = raw_stmt.get("Action", [])
        if isinstance(raw_actions, str):
            raw_actions = [raw_actions]
        actions = [CommonAction.from_string(a, provider="aws") for a in raw_actions]

        # Resources
        raw_resources = raw_stmt.get("Resource", ["*"])
        if isinstance(raw_resources, str):
            raw_resources = [raw_resources]
        resources = [
            CommonResource(arn_or_id=r, service=r.split(":")[2] if ":" in r and len(r.split(":")) > 2 else "")
            for r in raw_resources
        ]

        # Conditions
        conditions: List[CommonCondition] = []
        raw_conditions = raw_stmt.get("Condition", {})
        for operator, cond_map in raw_conditions.items():
            if isinstance(cond_map, dict):
                for key, vals in cond_map.items():
                    val_list = [str(v) for v in vals] if isinstance(vals, list) else [str(vals)]
                    conditions.append(CommonCondition(operator=operator, key=key, values=val_list))

        # Principals (if resource policy or trust policy)
        principals: List[CommonPrincipal] = []
        raw_principals = raw_stmt.get("Principal")
        if raw_principals:
            if isinstance(raw_principals, str):
                principals.append(CommonPrincipal(id=raw_principals, name=raw_principals, provider="aws"))
            elif isinstance(raw_principals, dict):
                for p_type, p_vals in raw_principals.items():
                    val_items = [p_vals] if isinstance(p_vals, str) else p_vals
                    for val in val_items:
                        principals.append(CommonPrincipal(id=val, name=val, type=p_type.lower(), provider="aws"))

        ir_statements.append(
            CommonStatement(
                sid=sid,
                effect=effect,
                actions=actions,
                resources=resources,
                conditions=conditions,
                principals=principals,
                provider_metadata={"original_statement": raw_stmt},
            )
        )

    return CommonPolicy(
        id=policy_id,
        name=name,
        provider="aws",
        version=version,
        statements=ir_statements,
        provider_metadata={"aws_version": version},
    )


def ir_to_aws_policy(common_policy: CommonPolicy) -> Dict[str, Any]:
    """Translates Common IAM IR into standard AWS IAM policy JSON dictionary."""
    enforce_provider_match("aws", common_policy.provider, context="AWS policy export")

    statements: List[Dict[str, Any]] = []

    for stmt in common_policy.statements:
        actions = [a.raw_action for a in stmt.actions]
        resources = [r.arn_or_id for r in stmt.resources] or ["*"]

        stmt_dict: Dict[str, Any] = {
            "Effect": stmt.effect.value,
            "Action": actions if len(actions) > 1 else (actions[0] if actions else "*"),
            "Resource": resources if len(resources) > 1 else resources[0],
        }

        if stmt.sid:
            stmt_dict["Sid"] = stmt.sid

        if stmt.conditions:
            cond_dict: Dict[str, Dict[str, Any]] = {}
            for c in stmt.conditions:
                if c.operator not in cond_dict:
                    cond_dict[c.operator] = {}
                cond_dict[c.operator][c.key] = c.values if len(c.values) > 1 else (c.values[0] if c.values else "")
            stmt_dict["Condition"] = cond_dict

        if stmt.principals:
            if len(stmt.principals) == 1 and stmt.principals[0].id == "*":
                stmt_dict["Principal"] = "*"
            else:
                p_dict: Dict[str, List[str]] = {}
                for p in stmt.principals:
                    ptype = "AWS" if p.type in ("service", "role", "user") else p.type
                    p_dict.setdefault(ptype, []).append(p.id)
                stmt_dict["Principal"] = {
                    k: v if len(v) > 1 else v[0] for k, v in p_dict.items()
                }

        statements.append(stmt_dict)

    version = common_policy.provider_metadata.get("aws_version", "2012-10-17")
    return {
        "Version": version,
        "Statement": statements,
    }


__all__ = [
    "aws_policy_to_ir",
    "ir_to_aws_policy",
]

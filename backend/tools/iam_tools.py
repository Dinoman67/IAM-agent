"""Deterministic IAM Tools wrapping environment operations, simulation, and verification."""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field

from backend.environment.loader import IAMEnvironment
from backend.environment.simulator import PolicySimulator
from backend.environment.verifier import PolicyVerifier
from backend.tools.base import BaseTool, ToolResult
from backend.tools.registry import ToolRegistry


# =====================================================================
# 1. get_principal
# =====================================================================
class GetPrincipalArgs(BaseModel):
    principal_id: str = Field(..., description="Unique ID of the principal to look up")


class GetPrincipalTool(BaseTool):
    name = "get_principal"
    description = "Retrieve principal identity details and assigned roles."
    args_schema = GetPrincipalArgs

    def __init__(self, env: IAMEnvironment) -> None:
        self.env = env

    def _execute(self, args: GetPrincipalArgs) -> ToolResult:
        principal = self.env.get_principal(args.principal_id)
        if not principal:
            return ToolResult(
                success=False,
                error=f"Principal '{args.principal_id}' not found.",
            )
        return ToolResult(
            success=True,
            data=principal.model_dump(),
            metadata={"principal_id": args.principal_id},
        )


# =====================================================================
# 2. get_role
# =====================================================================
class GetRoleArgs(BaseModel):
    role_id: str = Field(..., description="Unique identifier of the role")


class GetRoleTool(BaseTool):
    name = "get_role"
    description = "Retrieve role metadata, active permissions, and policy version history."
    args_schema = GetRoleArgs

    def __init__(self, env: IAMEnvironment) -> None:
        self.env = env

    def _execute(self, args: GetRoleArgs) -> ToolResult:
        role = self.env.get_role(args.role_id)
        if not role:
            return ToolResult(
                success=False,
                error=f"Role '{args.role_id}' not found.",
            )
        return ToolResult(
            success=True,
            data={
                "id": role.id,
                "name": role.name,
                "description": role.description,
                "current_version": role.current_version,
                "active_permissions": role.active_permissions(),
                "policy_versions": [v.model_dump() for v in role.policy_versions],
            },
            metadata={"role_id": args.role_id},
        )


# =====================================================================
# 3. get_access_history
# =====================================================================
class GetAccessHistoryArgs(BaseModel):
    role_id: Optional[str] = Field(default=None, description="Filter logs by role ID")
    principal_id: Optional[str] = Field(default=None, description="Filter logs by principal ID")


class GetAccessHistoryTool(BaseTool):
    name = "get_access_history"
    description = "Inspect historical access and CloudTrail execution logs for a role or principal."
    args_schema = GetAccessHistoryArgs

    def __init__(self, env: IAMEnvironment) -> None:
        self.env = env

    def _execute(self, args: GetAccessHistoryArgs) -> ToolResult:
        logs = self.env.get_access_history(
            role_id=args.role_id, principal_id=args.principal_id
        )
        return ToolResult(
            success=True,
            data=[log.model_dump() for log in logs],
            metadata={"count": len(logs)},
        )


# =====================================================================
# 4. list_permissions
# =====================================================================
class ListPermissionsArgs(BaseModel):
    role_id: str = Field(..., description="Target role ID")


class ListPermissionsTool(BaseTool):
    name = "list_permissions"
    description = "List all active permissions granted to a given IAM role."
    args_schema = ListPermissionsArgs

    def __init__(self, env: IAMEnvironment) -> None:
        self.env = env

    def _execute(self, args: ListPermissionsArgs) -> ToolResult:
        try:
            permissions = self.env.list_permissions(args.role_id)
            return ToolResult(
                success=True,
                data=permissions,
                metadata={"role_id": args.role_id, "count": len(permissions)},
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))


# =====================================================================
# 5. find_unused_permissions
# =====================================================================
class FindUnusedPermissionsArgs(BaseModel):
    role_id: str = Field(..., description="Target role ID")


class FindUnusedPermissionsTool(BaseTool):
    name = "find_unused_permissions"
    description = (
        "Identify permissions granted to a role that have never been observed in access logs."
    )
    args_schema = FindUnusedPermissionsArgs

    def __init__(self, env: IAMEnvironment) -> None:
        self.env = env

    def _execute(self, args: FindUnusedPermissionsArgs) -> ToolResult:
        try:
            unused = self.env.find_unused_permissions(args.role_id)
            return ToolResult(
                success=True,
                data=unused,
                metadata={"role_id": args.role_id, "unused_count": len(unused)},
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))


# =====================================================================
# 6. get_service_dependencies
# =====================================================================
class GetServiceDependenciesArgs(BaseModel):
    service: Optional[str] = Field(
        default=None, description="Filter dependencies by service name, e.g. 'PaymentService'"
    )


class GetServiceDependenciesTool(BaseTool):
    name = "get_service_dependencies"
    description = (
        "Discover transitive service dependencies (e.g. Service -> S3 -> KMS SSE encryption)."
    )
    args_schema = GetServiceDependenciesArgs

    def __init__(self, env: IAMEnvironment) -> None:
        self.env = env

    def _execute(self, args: GetServiceDependenciesArgs) -> ToolResult:
        deps = self.env.get_service_dependencies(service=args.service)
        return ToolResult(
            success=True,
            data=[d.model_dump() for d in deps],
            metadata={"count": len(deps)},
        )


# =====================================================================
# 7. simulate_policy
# =====================================================================
class SimulatePolicyArgs(BaseModel):
    role_id: str = Field(..., description="Target role ID")
    proposed_permissions: Optional[List[str]] = Field(
        default=None, description="Explicit proposed active permissions"
    )
    remove_permissions: Optional[List[str]] = Field(
        default=None, description="Permissions proposed to be removed from current policy"
    )


class SimulatePolicyTool(BaseTool):
    name = "simulate_policy"
    description = (
        "Simulate impact of candidate permissions on required workflows before applying changes."
    )
    args_schema = SimulatePolicyArgs

    def __init__(self, env: IAMEnvironment) -> None:
        self.env = env
        self.simulator = PolicySimulator(env)

    def _execute(self, args: SimulatePolicyArgs) -> ToolResult:
        role = self.env.get_role(args.role_id)
        if not role:
            return ToolResult(success=False, error=f"Role '{args.role_id}' not found.")

        if args.proposed_permissions is not None:
            perms_to_test = args.proposed_permissions
        elif args.remove_permissions is not None:
            current = role.active_permissions()
            perms_to_test = [p for p in current if p not in args.remove_permissions]
        else:
            perms_to_test = role.active_permissions()

        sim_result = self.simulator.simulate(args.role_id, perms_to_test)
        return ToolResult(
            success=True,
            data=sim_result.model_dump(),
            metadata={"simulation_success": sim_result.success, "evidence_id": sim_result.evidence_id},
        )


# =====================================================================
# 8. apply_policy_change
# =====================================================================
class ApplyPolicyChangeArgs(BaseModel):
    role_id: str = Field(..., description="Role ID to mutate")
    remove_permissions: Optional[List[str]] = Field(
        default=None, description="Permissions to remove from active policy"
    )
    keep_permissions: Optional[List[str]] = Field(
        default=None, description="Explicit permissions to retain"
    )
    new_permissions: Optional[List[str]] = Field(
        default=None, description="Complete replacement list of permissions"
    )
    reason: str = Field(..., description="Audit reason for policy change")


class ApplyPolicyChangeTool(BaseTool):
    name = "apply_policy_change"
    description = (
        "Deterministically apply a structured policy change, producing a new immutable policy version."
    )
    args_schema = ApplyPolicyChangeArgs

    def __init__(self, env: IAMEnvironment) -> None:
        self.env = env

    def _execute(self, args: ApplyPolicyChangeArgs) -> ToolResult:
        role = self.env.get_role(args.role_id)
        if not role:
            return ToolResult(success=False, error=f"Role '{args.role_id}' not found.")

        current = role.active_permissions()

        if args.new_permissions is not None:
            final_perms = args.new_permissions
        elif args.keep_permissions is not None:
            final_perms = args.keep_permissions
        elif args.remove_permissions is not None:
            final_perms = [p for p in current if p not in args.remove_permissions]
        else:
            return ToolResult(
                success=False,
                error="Must specify one of 'new_permissions', 'keep_permissions', or 'remove_permissions'.",
            )

        try:
            new_version = self.env.apply_policy_version(
                role_id=args.role_id,
                new_permissions=final_perms,
                reason=args.reason,
            )
            return ToolResult(
                success=True,
                data=new_version.model_dump(),
                metadata={"version_id": new_version.version_id, "role_id": args.role_id},
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))


# =====================================================================
# 9. verify_required_access
# =====================================================================
class VerifyRequiredAccessArgs(BaseModel):
    role_id: str = Field(..., description="Target role ID")


class VerifyRequiredAccessTool(BaseTool):
    name = "verify_required_access"
    description = (
        "Deterministically verify that application workflows succeed and protected resources are secure."
    )
    args_schema = VerifyRequiredAccessArgs

    def __init__(self, env: IAMEnvironment) -> None:
        self.env = env
        self.verifier = PolicyVerifier(env)

    def _execute(self, args: VerifyRequiredAccessArgs) -> ToolResult:
        v_result = self.verifier.verify(args.role_id)
        return ToolResult(
            success=True,
            data=v_result.model_dump(),
            metadata={"passed": v_result.passed},
        )


# =====================================================================
# 10. rollback_policy
# =====================================================================
class RollbackPolicyArgs(BaseModel):
    role_id: str = Field(..., description="Target role ID")
    target_version: str = Field(default="v1", description="Policy version to restore")


class RollbackPolicyTool(BaseTool):
    name = "rollback_policy"
    description = "Restore a previous policy version for a role in case of verification failure."
    args_schema = RollbackPolicyArgs

    def __init__(self, env: IAMEnvironment) -> None:
        self.env = env

    def _execute(self, args: RollbackPolicyArgs) -> ToolResult:
        try:
            target = self.env.rollback_policy(args.role_id, args.target_version)
            return ToolResult(
                success=True,
                data=target.model_dump(),
                metadata={"restored_version": target.version_id},
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))


def create_default_tool_registry(env: IAMEnvironment) -> ToolRegistry:
    """Factory creating and registering all 10 IAM tools with the given environment."""
    registry = ToolRegistry()
    registry.register(GetPrincipalTool(env))
    registry.register(GetRoleTool(env))
    registry.register(GetAccessHistoryTool(env))
    registry.register(ListPermissionsTool(env))
    registry.register(FindUnusedPermissionsTool(env))
    registry.register(GetServiceDependenciesTool(env))
    registry.register(SimulatePolicyTool(env))
    registry.register(ApplyPolicyChangeTool(env))
    registry.register(VerifyRequiredAccessTool(env))
    registry.register(RollbackPolicyTool(env))
    return registry

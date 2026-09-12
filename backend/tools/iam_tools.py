"""Deterministic IAM Tools wrapping environment operations, simulation, and verification."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.environment.loader import IAMEnvironment
from backend.environment.simulator import PolicySimulator
from backend.environment.verifier import PolicyVerifier
from backend.providers.capabilities import AWS_CAPABILITIES, GCP_CAPABILITIES, AZURE_CAPABILITIES, ProviderCapabilities
from backend.security.diff import compute_policy_diff
from backend.tools.base import BaseTool, ToolResult
from backend.tools.registry import ToolRegistry


# =====================================================================
# 1. get_principal / inspect_principal
# =====================================================================
class GetPrincipalArgs(BaseModel):
    principal_id: str = Field(..., description="Unique ID of the principal to look up")


class GetPrincipalTool(BaseTool):
    name = "get_principal"
    description = "Retrieve principal identity details and assigned roles."
    args_schema = GetPrincipalArgs
    risk_classification = "read_only"

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


class InspectPrincipalTool(GetPrincipalTool):
    name = "inspect_principal"
    description = "Inspect principal identity details, assigned roles, and credentials."


# =====================================================================
# 2. get_role / inspect_role
# =====================================================================
class GetRoleArgs(BaseModel):
    role_id: str = Field(..., description="Unique identifier of the role")


class GetRoleTool(BaseTool):
    name = "get_role"
    description = "Retrieve role metadata, active permissions, and policy version history."
    args_schema = GetRoleArgs
    risk_classification = "read_only"

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


class InspectRoleTool(GetRoleTool):
    name = "inspect_role"
    description = "Inspect role definition, active permission set, and revision history."


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
    risk_classification = "read_only"

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
    risk_classification = "read_only"

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
    risk_classification = "read_only"

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
    risk_classification = "read_only"

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
# 7. simulate_policy / simulate_policy_change
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
    risk_classification = "simulation"

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


class SimulatePolicyChangeTool(SimulatePolicyTool):
    name = "simulate_policy_change"
    description = "Run counterfactual simulation on candidate permission changes against production workflows."


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
    risk_classification = "mutation"

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
    risk_classification = "read_only"

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
# 10. rollback_policy / rollback_policy_change
# =====================================================================
class RollbackPolicyArgs(BaseModel):
    role_id: str = Field(..., description="Target role ID")
    target_version: str = Field(default="v1", description="Policy version to restore")


class RollbackPolicyTool(BaseTool):
    name = "rollback_policy"
    description = "Restore a previous policy version for a role in case of verification failure."
    args_schema = RollbackPolicyArgs
    risk_classification = "mutation"

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


class RollbackPolicyChangeTool(RollbackPolicyTool):
    name = "rollback_policy_change"
    description = "Rollback active role policy to designated stable revision."


# =====================================================================
# 11. get_provider_capabilities
# =====================================================================
class GetProviderCapabilitiesArgs(BaseModel):
    provider_name: Optional[str] = Field(
        default="aws", description="Target cloud provider identifier, e.g. 'aws', 'gcp', 'azure'"
    )


class GetProviderCapabilitiesTool(BaseTool):
    name = "get_provider_capabilities"
    description = "Inspect provider capabilities (simulation, versioning, rollback, scoping) to ensure parity."
    args_schema = GetProviderCapabilitiesArgs
    risk_classification = "read_only"

    def __init__(self, env: IAMEnvironment) -> None:
        self.env = env

    def _execute(self, args: GetProviderCapabilitiesArgs) -> ToolResult:
        name = (args.provider_name or "aws").lower()
        if name == "aws":
            caps = AWS_CAPABILITIES
        elif name == "gcp":
            caps = GCP_CAPABILITIES
        elif name == "azure":
            caps = AZURE_CAPABILITIES
        else:
            caps = ProviderCapabilities(provider_name=name)

        return ToolResult(
            success=True,
            data=caps.model_dump(),
            metadata={"provider_name": name},
        )


# =====================================================================
# 12. compute_policy_diff
# =====================================================================
class ComputePolicyDiffArgs(BaseModel):
    role_id: str = Field(..., description="Target role ID")
    proposed_permissions: Optional[List[str]] = Field(
        default=None, description="Proposed active permissions"
    )
    remove_permissions: Optional[List[str]] = Field(
        default=None, description="Permissions proposed to be removed"
    )
    retained_dependencies: Optional[List[str]] = Field(
        default=None, description="List of retained transitive dependencies"
    )


class ComputePolicyDiffTool(BaseTool):
    name = "compute_policy_diff"
    description = "Compute structured before/after diff of policy changes including added, removed, and kept permissions."
    args_schema = ComputePolicyDiffArgs
    risk_classification = "read_only"

    def __init__(self, env: IAMEnvironment) -> None:
        self.env = env

    def _execute(self, args: ComputePolicyDiffArgs) -> ToolResult:
        role = self.env.get_role(args.role_id)
        if not role:
            return ToolResult(success=False, error=f"Role '{args.role_id}' not found.")

        current = role.active_permissions()
        if args.proposed_permissions is not None:
            new_perms = args.proposed_permissions
        elif args.remove_permissions is not None:
            new_perms = [p for p in current if p not in args.remove_permissions]
        else:
            new_perms = current

        diff = compute_policy_diff(
            role_id=args.role_id,
            from_version=role.current_version,
            original_permissions=current,
            new_permissions=new_perms,
            retained_dependencies=args.retained_dependencies,
        )

        return ToolResult(
            success=True,
            data=diff.model_dump(),
            metadata={"removed_count": len(diff.removed), "kept_count": len(diff.kept)},
        )


# =====================================================================
# 13. check_security_invariants
# =====================================================================
class CheckSecurityInvariantsArgs(BaseModel):
    role_id: str = Field(..., description="Target role ID")
    proposed_permissions: Optional[List[str]] = Field(
        default=None, description="Permissions to evaluate against invariants"
    )


class CheckSecurityInvariantsTool(BaseTool):
    name = "check_security_invariants"
    description = "Validate candidate policy against protected permissions and sensitive resource isolation."
    args_schema = CheckSecurityInvariantsArgs
    risk_classification = "read_only"

    def __init__(self, env: IAMEnvironment) -> None:
        self.env = env

    def _execute(self, args: CheckSecurityInvariantsArgs) -> ToolResult:
        role = self.env.get_role(args.role_id)
        if not role:
            return ToolResult(success=False, error=f"Role '{args.role_id}' not found.")

        perms = (
            args.proposed_permissions
            if args.proposed_permissions is not None
            else role.active_permissions()
        )

        exposed_protected: List[str] = []
        for resource in self.env.data.resources:
            if resource.is_protected:
                for req_perm in resource.required_permissions:
                    if PolicySimulator.is_action_allowed(req_perm, perms):
                        exposed_protected.append(f"{resource.id} via '{req_perm}'")

        wildcards = [p for p in perms if "*" in p]

        invariants_satisfied = len(exposed_protected) == 0 and len(wildcards) == 0

        return ToolResult(
            success=True,
            data={
                "invariants_satisfied": invariants_satisfied,
                "exposed_protected_resources": exposed_protected,
                "retained_wildcards": wildcards,
            },
            metadata={"invariants_satisfied": invariants_satisfied},
        )


def create_default_tool_registry(env: IAMEnvironment) -> ToolRegistry:
    """Factory creating and registering the 10 core deterministic IAM tools (Phase 1 contract)."""
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


def create_extended_tool_registry(env: IAMEnvironment) -> ToolRegistry:
    """Factory creating core IAM tools plus Phase 2 extensions and aliases."""
    registry = create_default_tool_registry(env)

    # Phase 2 extension tools
    registry.register(GetProviderCapabilitiesTool(env))
    registry.register(ComputePolicyDiffTool(env))
    registry.register(CheckSecurityInvariantsTool(env))

    # Aliases
    registry.register(InspectPrincipalTool(env))
    registry.register(InspectRoleTool(env))
    registry.register(SimulatePolicyChangeTool(env))
    registry.register(RollbackPolicyChangeTool(env))

    return registry

"""Deterministic IAM Tools wrapping environment operations, simulation, and verification."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.environment.loader import IAMEnvironment
from backend.environment.simulator import PolicySimulator
from backend.environment.verifier import PolicyVerifier
from backend.models.iam import CommonPolicy
from backend.providers.capabilities import AWS_CAPABILITIES, GCP_CAPABILITIES, AZURE_CAPABILITIES, ProviderCapabilities
from backend.security.analyzer import SecurityAnalyzer
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
# 7. simulate_policy / simulate_policy_change / simulate_change
# =====================================================================
class SimulatePolicyArgs(BaseModel):
    role_id: str = Field(..., description="Target role ID")
    proposed_permissions: Optional[List[str]] = Field(
        default=None, description="Explicit proposed active permissions"
    )
    remove_permissions: Optional[List[str]] = Field(
        default=None, description="Permissions proposed to be removed from current policy"
    )
    provider: Optional[str] = Field(
        default="aws", description="Target cloud provider (aws, gcp, azure)"
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
        prov = (args.provider or "aws").lower()
        if prov in ("gcp", "azure"):
            return ToolResult(
                success=False,
                data=None,
                error=f"UNSUPPORTED_CAPABILITY: Local {prov.upper()} simulation is not implemented.",
                metadata={
                    "unsupported_capability": True,
                    "provider": prov,
                    "operation": "simulate_change",
                    "reason": f"Provider '{prov}' does not support local policy simulation in this environment.",
                },
            )

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
            metadata={"simulation_success": sim_result.success, "evidence_id": sim_result.evidence_id, "provider": prov},
        )


class SimulatePolicyChangeTool(SimulatePolicyTool):
    name = "simulate_policy_change"
    description = "Run counterfactual simulation on candidate permission changes against production workflows."


class SimulateChangeTool(SimulatePolicyTool):
    name = "simulate_change"
    description = "Provider-neutral pre-commit simulation of candidate policy changes against application workflows."


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


class ApplyChangeTool(ApplyPolicyChangeTool):
    name = "apply_change"
    description = "Provider-neutral policy modification tool applying candidate policy changes."


# =====================================================================
# 9. verify_required_access / verify_change
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


class VerifyChangeTool(VerifyRequiredAccessTool):
    name = "verify_change"
    description = "Provider-neutral post-remediation verification checking workflows and security invariants."


# =====================================================================
# 10. rollback_policy / rollback_policy_change / rollback_change
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


class RollbackChangeTool(RollbackPolicyTool):
    name = "rollback_change"
    description = "Provider-neutral rollback tool restoring a designated stable policy revision."


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


# =====================================================================
# 14. inspect_policy
# =====================================================================
class InspectPolicyArgs(BaseModel):
    role_id: Optional[str] = Field(default=None, description="Role ID to extract policy from")
    policy_id: Optional[str] = Field(default=None, description="Direct policy ID")


class InspectPolicyTool(BaseTool):
    name = "inspect_policy"
    description = "Inspect an IAM policy document and statements in provider-neutral Common IR."
    args_schema = InspectPolicyArgs
    risk_classification = "read_only"

    def __init__(self, env: IAMEnvironment) -> None:
        self.env = env

    def _execute(self, args: InspectPolicyArgs) -> ToolResult:
        role_id = args.role_id
        if not role_id and not args.policy_id:
            role_id = "PaymentServiceRole"
        elif not role_id and args.policy_id:
            role_id = args.policy_id.replace("policy-", "").replace("Policy", "")

        role = self.env.get_role(role_id)
        if not role:
            return ToolResult(success=False, error=f"Role or policy for '{role_id}' not found.")

        common_policy = CommonPolicy.from_permissions_list(
            policy_id=f"policy-{role.id}",
            name=f"{role.name}Policy",
            permissions=role.active_permissions(),
            version=role.current_version,
            provider="aws",
        )
        return ToolResult(
            success=True,
            data=common_policy.model_dump(),
            metadata={"role_id": role.id, "version": role.current_version},
        )


# =====================================================================
# 15. analyze_policy
# =====================================================================
class AnalyzePolicyArgs(BaseModel):
    role_id: str = Field(..., description="Target role ID to analyze permissions and build structured evidence bundles")


class AnalyzePolicyTool(BaseTool):
    name = "analyze_policy"
    description = (
        "Deterministically analyze granted permissions against access history, transitive dependencies, "
        "and security rules, producing structured EvidenceBundles."
    )
    args_schema = AnalyzePolicyArgs
    risk_classification = "read_only"

    def __init__(self, env: IAMEnvironment) -> None:
        self.env = env
        self.analyzer = SecurityAnalyzer(env)

    def _execute(self, args: AnalyzePolicyArgs) -> ToolResult:
        role = self.env.get_role(args.role_id)
        if not role:
            return ToolResult(success=False, error=f"Role '{args.role_id}' not found.")

        bundles = self.analyzer.analyze_role(args.role_id)
        serialized = {perm: bundle.model_dump() for perm, bundle in bundles.items()}
        return ToolResult(
            success=True,
            data=serialized,
            metadata={"role_id": args.role_id, "analyzed_permissions": list(bundles.keys())},
        )


class AnalyzePermissionsTool(AnalyzePolicyTool):
    name = "analyze_permissions"
    description = "Provider-neutral permission analysis tool building structured evidence bundles."


# =====================================================================
# 16. validate_change
# =====================================================================
class ValidateChangeArgs(BaseModel):
    role_id: Optional[str] = Field(default=None, description="Target role ID")
    proposed_permissions: Optional[List[str]] = Field(default=None, description="Proposed permissions")
    provider: Optional[str] = Field(default="aws", description="Cloud provider: aws, gcp, azure")
    policy_document: Optional[Dict[str, Any]] = Field(default=None, description="Explicit raw policy document")


class ValidateChangeTool(BaseTool):
    name = "validate_change"
    description = "Validate candidate policy changes against provider-specific syntax, schema, and security invariants."
    args_schema = ValidateChangeArgs
    risk_classification = "read_only"

    def __init__(self, env: IAMEnvironment) -> None:
        self.env = env

    def _execute(self, args: ValidateChangeArgs) -> ToolResult:
        from backend.security.validator import (
            validate_aws_policy,
            validate_gcp_binding,
            validate_azure_assignment,
        )
        prov = (args.provider or "aws").lower()
        if prov == "aws":
            if args.policy_document:
                res = validate_aws_policy(args.policy_document)
            else:
                perms = args.proposed_permissions or []
                policy = CommonPolicy.from_permissions_list(
                    policy_id=args.role_id or "candidate",
                    name="CandidatePolicy",
                    permissions=perms,
                    provider="aws",
                )
                res = validate_aws_policy(policy)
        elif prov == "gcp":
            res = validate_gcp_binding(
                args.policy_document
                or {
                    "role": f"roles/{args.role_id or 'customRole'}",
                    "members": ["serviceAccount:sa@proj.iam.gserviceaccount.com"],
                }
            )
        elif prov == "azure":
            res = validate_azure_assignment(
                args.policy_document
                or {
                    "properties": {
                        "roleDefinitionId": args.role_id or "/providers/Microsoft.Authorization/roleDefinitions/def-1",
                        "principalId": "sp-id",
                        "scope": "/subscriptions/sub-1",
                    }
                }
            )
        else:
            return ToolResult(success=False, error=f"Unknown provider: {prov}")

        return ToolResult(
            success=res.is_valid,
            data=res.model_dump(),
            metadata={"is_valid": res.is_valid, "provider": prov, "error_count": len(res.errors)},
        )


# =====================================================================
# Hero tools: attack graph, temporal mining, live AWS, Terraform export
# =====================================================================
class AttackGraphArgs(BaseModel):
    role_id: str = Field(..., description="Target role ID")


class GetAttackGraphTool(BaseTool):
    name = "get_attack_graph"
    description = "Compute attacker-reachable resources and protected paths if this role is compromised."
    args_schema = AttackGraphArgs
    risk_classification = "read_only"

    def __init__(self, env: IAMEnvironment) -> None:
        self.env = env

    def _execute(self, args: AttackGraphArgs) -> ToolResult:
        from backend.security.attack_graph import compute_attack_graph

        try:
            graph = compute_attack_graph(args.role_id, self.env)
        except ValueError as ex:
            return ToolResult(success=False, error=str(ex))
        return ToolResult(success=True, data=graph.model_dump())


class TemporalArgs(BaseModel):
    role_id: str = Field(..., description="Target role ID")
    window_days: int = Field(default=365, description="Lookback window in days")


class AnalyzeTemporalTool(BaseTool):
    name = "analyze_temporal_usage"
    description = "Classify permissions as FREQUENT / RARE_BUT_CRITICAL / SEASONAL / DEAD over time."
    args_schema = TemporalArgs
    risk_classification = "read_only"

    def __init__(self, env: IAMEnvironment) -> None:
        self.env = env

    def _execute(self, args: TemporalArgs) -> ToolResult:
        from backend.security.temporal import classify_permissions

        try:
            report = classify_permissions(args.role_id, self.env, window_days=args.window_days)
        except ValueError as ex:
            return ToolResult(success=False, error=str(ex))
        return ToolResult(success=True, data=report.model_dump())


class EmptyArgs(BaseModel):
    pass


class AWSLiveStatusTool(BaseTool):
    name = "aws_live_status"
    description = "Probe read-only AWS connectivity (never mutates; falls back to simulator)."
    args_schema = EmptyArgs
    risk_classification = "read_only"

    def __init__(self, env: IAMEnvironment) -> None:
        self.env = env

    def _execute(self, args: EmptyArgs) -> ToolResult:
        from backend.connectors.aws_readonly import AWSReadOnlyConnector

        return ToolResult(success=True, data=AWSReadOnlyConnector().status())


class ExportTerraformArgs(BaseModel):
    role_id: str = Field(..., description="Target role ID")
    permissions: Optional[List[str]] = Field(default=None, description="Proposed permissions (default: active)")


class ExportTerraformTool(BaseTool):
    name = "export_terraform"
    description = "Export least-privilege policy as Terraform HCL + GitHub PR body with gates."
    args_schema = ExportTerraformArgs
    risk_classification = "read_only"

    def __init__(self, env: IAMEnvironment) -> None:
        self.env = env

    def _execute(self, args: ExportTerraformArgs) -> ToolResult:
        from backend.export.terraform import build_pr_body, to_terraform_hcl
        from backend.security.attack_graph import compute_attack_graph, paths_blocked
        from backend.security.blast_radius import calculate_blast_radius
        from backend.security.temporal import classify_permissions

        role = self.env.get_role(args.role_id)
        if not role:
            return ToolResult(success=False, error=f"Role '{args.role_id}' not found.")
        original = role.active_permissions()
        proposed = args.permissions or original
        graph = compute_attack_graph(args.role_id, self.env)
        temporal = classify_permissions(args.role_id, self.env)
        blast = calculate_blast_radius(original, proposed)
        hcl = to_terraform_hcl(args.role_id, proposed)
        pr = build_pr_body(
            role_id=args.role_id,
            removed=sorted(set(original) - set(proposed)),
            retained=sorted(set(original) & set(proposed)),
            blast_level=blast.level,
            blast_score=blast.score,
            attack_paths_blocked=paths_blocked(graph, proposed, self.env),
            temporal_retained=[f.permission for f in temporal.findings if f.classification == "RARE_BUT_CRITICAL"],
        )
        return ToolResult(success=True, data={"hcl": hcl, "pr_body": pr, "blast": blast.model_dump()})


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
    """Factory creating core IAM tools plus Phase 2 and Phase 3 provider-neutral tools."""
    registry = create_default_tool_registry(env)

    # Phase 2 extension tools
    registry.register(GetProviderCapabilitiesTool(env))
    registry.register(ComputePolicyDiffTool(env))
    registry.register(CheckSecurityInvariantsTool(env))
    registry.register(InspectPolicyTool(env))
    registry.register(AnalyzePolicyTool(env))

    # Phase 2 Aliases
    registry.register(InspectPrincipalTool(env))
    registry.register(InspectRoleTool(env))
    registry.register(SimulatePolicyChangeTool(env))
    registry.register(RollbackPolicyChangeTool(env))

    # Phase 3 Provider-Neutral Canonical Tools
    registry.register(ValidateChangeTool(env))
    registry.register(SimulateChangeTool(env))
    registry.register(VerifyChangeTool(env))
    registry.register(ApplyChangeTool(env))
    registry.register(RollbackChangeTool(env))
    registry.register(AnalyzePermissionsTool(env))

    # Hero tools: attack graph, temporal mining, live AWS status, Terraform export
    registry.register(GetAttackGraphTool(env))
    registry.register(AnalyzeTemporalTool(env))
    registry.register(AWSLiveStatusTool(env))
    registry.register(ExportTerraformTool(env))

    return registry


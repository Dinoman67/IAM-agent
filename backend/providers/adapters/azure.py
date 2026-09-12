"""Microsoft Azure IAM / RBAC provider adapter implementation."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from backend.models.iam import CommonAction, CommonBinding, CommonPolicy, CommonPrincipal, CommonResource, CommonStatement, PolicyEffect
from backend.models.schemas import PolicyVersion, SimulationResult
from backend.providers.base import BaseProvider, ProviderValidationResult
from backend.providers.capabilities import AZURE_CAPABILITIES, ProviderCapabilities
from backend.providers.common.errors import UnsupportedCapabilityError, enforce_provider_match
from backend.security.diff import PolicyDiff, compute_policy_diff
from backend.security.validator import validate_azure_assignment
from backend.security.verification import ComprehensiveVerificationResult


class AzureProviderAdapter(BaseProvider):
    """Adapter for Microsoft Azure IAM RBAC.

    Reflects authentic Azure RBAC capabilities:
    - No native pre-commit simulation (supports_policy_simulation=False)
    - Role definitions and role assignments without immutable version history (supports_policy_versioning=False)
    - No atomic rollback (supports_rollback=False)
    """

    def __init__(
        self,
        capabilities: Optional[ProviderCapabilities] = None,
        roles_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._capabilities = capabilities or AZURE_CAPABILITIES
        self._roles_data = roles_data or {
            "Contributor": {
                "roleName": "Contributor",
                "permissions": [
                    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
                    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
                ],
                "scope": "/subscriptions/sub-123",
            },
            "Reader": {
                "roleName": "Reader",
                "permissions": [
                    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
                ],
                "scope": "/subscriptions/sub-123",
            },
        }

    def get_capabilities(self) -> ProviderCapabilities:
        return self._capabilities

    def inspect_principal(self, principal_id: str) -> Optional[CommonPrincipal]:
        return CommonPrincipal(
            id=principal_id,
            name=principal_id,
            type="service_principal",
            provider="azure",
            roles=[r for r, d in self._roles_data.items() if principal_id in d.get("members", [])],
            provider_metadata={"principalType": "ServicePrincipal"},
        )

    def inspect_policy(self, policy_id: str) -> Optional[CommonPolicy]:
        role_info = self._roles_data.get(policy_id, {})
        permissions = role_info.get(
            "permissions",
            ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"],
        )
        actions = [CommonAction.from_string(p, provider="azure") for p in permissions]
        stmt = CommonStatement(
            sid="RolePermissions",
            effect=PolicyEffect.ALLOW,
            actions=actions,
            resources=[CommonResource(arn_or_id="*", scope=role_info.get("scope", "/"))],
        )

        return CommonPolicy(
            id=f"/subscriptions/sub-id/providers/Microsoft.Authorization/roleDefinitions/{policy_id}",
            name=policy_id,
            provider="azure",
            version="1.0",
            statements=[stmt],
            provider_metadata={"assignableScopes": [role_info.get("scope", "/")]},
        )

    def analyze_permissions(self, role_id: str) -> Dict[str, Any]:
        policy = self.inspect_policy(role_id)
        if not policy:
            return {}
        perms = policy.extract_permission_strings()
        return {
            p: {
                "permission": p,
                "provider": "azure",
                "state": "ASSIGNED",
                "risk": "high" if "write" in p or "delete" in p or "*" in p else "low",
            }
            for p in perms
        }

    def compute_policy_diff(
        self,
        role_id: str,
        from_version: str,
        original_permissions: List[str],
        new_permissions: List[str],
        to_version: Optional[str] = None,
        retained_dependencies: Optional[List[str]] = None,
    ) -> PolicyDiff:
        return compute_policy_diff(
            role_id=role_id,
            from_version=from_version,
            original_permissions=original_permissions,
            new_permissions=new_permissions,
            to_version=to_version,
            retained_dependencies=retained_dependencies,
            provider="azure",
        )

    def simulate_change(self, role_id: str, proposed_permissions: List[str]) -> SimulationResult:
        """Simulation is not natively supported by Azure RBAC."""
        raise UnsupportedCapabilityError(
            provider="azure",
            operation="simulate_change",
            reason="Provider 'azure' does not support native pre-commit simulation. Requires Azure Policy evaluation or escalation.",
            limitations=["No provider-native simulator in this adapter", "Azure Policy dry-run not available locally"],
        )

    def validate_change(self, target: Any) -> ProviderValidationResult:
        return validate_azure_assignment(target)

    def verify_change(
        self, role_id: str, expected_permissions: Optional[List[str]] = None
    ) -> ComprehensiveVerificationResult:
        policy = self.inspect_policy(role_id)
        if not policy:
            return ComprehensiveVerificationResult(
                passed=False,
                functional_passed=False,
                security_passed=False,
                structural_passed=False,
                provider_passed=False,
                checks={"role_exists": False},
                details=[f"Azure role '{role_id}' not found"],
            )

        active = policy.extract_permission_strings()
        structural_passed = True
        if expected_permissions is not None:
            structural_passed = set(active) == set(expected_permissions)

        return ComprehensiveVerificationResult(
            passed=structural_passed,
            functional_passed=True,
            security_passed=True,
            structural_passed=structural_passed,
            provider_passed=True,
            checks={"structural_passed": structural_passed, "provider_passed": True},
            details=["Azure role assignment verification complete."],
        )

    def apply_change(self, role_id: str, new_permissions: List[str], reason: str) -> PolicyVersion:
        version_obj = PolicyVersion(
            version_id="rev-updated",
            permissions=new_permissions,
            created_by="agent",
            reason=reason,
        )
        if role_id in self._roles_data:
            self._roles_data[role_id]["permissions"] = new_permissions
        return version_obj

    def rollback_change(self, role_id: str, target_version: str) -> PolicyVersion:
        """Atomic rollback is not natively supported on Azure."""
        raise UnsupportedCapabilityError(
            provider="azure",
            operation="rollback_change",
            reason="Provider 'azure' does not support atomic policy rollback. Role assignment modification must be escalated or re-created.",
            limitations=["Role assignment recreation required", "No revision history tracking in Azure RBAC"],
        )


class SimulatedAzureProvider(AzureProviderAdapter):
    """Explicit alias for simulated Azure provider."""
    pass


class RealAzureProvider(BaseProvider):
    """Production Azure RBAC connector stub with disabled-by-default safeguards."""

    def __init__(self, subscription_id: str = "default-sub") -> None:
        self.subscription_id = subscription_id
        self._capabilities = AZURE_CAPABILITIES
        self._live_mutation_enabled = os.getenv("LIVE_MUTATION_ENABLED", "false").lower() in ("true", "1")

    def get_capabilities(self) -> ProviderCapabilities:
        return self._capabilities

    def inspect_principal(self, principal_id: str) -> Optional[CommonPrincipal]:
        raise NotImplementedError("RealAzureProvider requires Azure Entra ID credentials.")

    def inspect_policy(self, policy_id: str) -> Optional[CommonPolicy]:
        raise NotImplementedError("RealAzureProvider requires Azure Resource Manager credentials.")

    def analyze_permissions(self, role_id: str) -> Dict[str, Any]:
        raise NotImplementedError("RealAzureProvider requires Azure RBAC credentials.")

    def compute_policy_diff(
        self,
        role_id: str,
        from_version: str,
        original_permissions: List[str],
        new_permissions: List[str],
        to_version: Optional[str] = None,
        retained_dependencies: Optional[List[str]] = None,
    ) -> PolicyDiff:
        return compute_policy_diff(
            role_id=role_id,
            from_version=from_version,
            original_permissions=original_permissions,
            new_permissions=new_permissions,
            to_version=to_version,
            retained_dependencies=retained_dependencies,
            provider="azure",
        )

    def simulate_change(self, role_id: str, proposed_permissions: List[str]) -> SimulationResult:
        raise UnsupportedCapabilityError(
            provider="azure",
            operation="simulate_change",
            reason="Azure live policy simulation is unsupported in this environment.",
        )

    def validate_change(self, target: Any) -> ProviderValidationResult:
        return validate_azure_assignment(target)

    def verify_change(
        self, role_id: str, expected_permissions: Optional[List[str]] = None
    ) -> ComprehensiveVerificationResult:
        raise NotImplementedError("RealAzureProvider verification requires live credentials.")

    def apply_change(self, role_id: str, new_permissions: List[str], reason: str) -> PolicyVersion:
        if not self._live_mutation_enabled:
            raise PermissionError("Live Azure mutation is disabled by default.")
        raise NotImplementedError("Live Azure mutation is not enabled.")

    def rollback_change(self, role_id: str, target_version: str) -> PolicyVersion:
        raise UnsupportedCapabilityError(
            provider="azure",
            operation="rollback_change",
            reason="Azure does not support atomic rollback.",
        )


__all__ = [
    "AzureProviderAdapter",
    "SimulatedAzureProvider",
    "RealAzureProvider",
]

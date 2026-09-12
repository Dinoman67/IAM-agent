"""Google Cloud Platform (GCP) IAM provider adapter implementation."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from backend.models.iam import CommonAction, CommonBinding, CommonPolicy, CommonPrincipal, CommonResource, CommonStatement, PolicyEffect
from backend.models.schemas import PolicyVersion, SimulationResult
from backend.providers.base import BaseProvider, ProviderValidationResult
from backend.providers.capabilities import GCP_CAPABILITIES, ProviderCapabilities
from backend.providers.common.errors import UnsupportedCapabilityError, enforce_provider_match
from backend.security.diff import PolicyDiff, compute_policy_diff
from backend.security.validator import validate_gcp_binding
from backend.security.verification import ComprehensiveVerificationResult


class GCPProviderAdapter(BaseProvider):
    """Adapter for Google Cloud Platform IAM.

    Reflects authentic GCP capabilities:
    - No native pre-commit simulation (supports_policy_simulation=False)
    - Etag-based concurrency rather than native immutable versioning (supports_policy_versioning=False)
    - No atomic rollback (supports_rollback=False)
    """

    def __init__(
        self,
        capabilities: Optional[ProviderCapabilities] = None,
        roles_data: Optional[Dict[str, Any]] = None,
        bindings_data: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self._capabilities = capabilities or GCP_CAPABILITIES
        self._roles_data = roles_data or {
            "roles/storage.objectViewer": {
                "title": "Storage Object Viewer",
                "permissions": ["storage.objects.get", "storage.objects.list"],
                "etag": "etag-1",
            },
            "roles/editor": {
                "title": "Editor",
                "permissions": ["storage.objects.get", "storage.objects.create", "compute.instances.get"],
                "etag": "etag-1",
            },
        }
        self._bindings_data = bindings_data or []

    def get_capabilities(self) -> ProviderCapabilities:
        return self._capabilities

    def inspect_principal(self, principal_id: str) -> Optional[CommonPrincipal]:
        # Formats GCP service accounts e.g. serviceAccount:my-sa@project.iam.gserviceaccount.com
        ptype = "service_account" if ("serviceAccount:" in principal_id or "@" in principal_id) else "user"
        assigned_roles = []
        for role_id, rdata in self._roles_data.items():
            if principal_id in rdata.get("members", []):
                assigned_roles.append(role_id)

        return CommonPrincipal(
            id=principal_id,
            name=principal_id.split("@")[0] if "@" in principal_id else principal_id,
            type=ptype,
            provider="gcp",
            roles=assigned_roles,
            provider_metadata={"member_type": ptype},
        )

    def inspect_policy(self, policy_id: str) -> Optional[CommonPolicy]:
        role_key = policy_id if policy_id.startswith("roles/") else f"roles/{policy_id}"
        role_info = self._roles_data.get(role_key) or self._roles_data.get(policy_id, {})
        permissions = role_info.get("permissions", ["storage.objects.get", "storage.objects.create"])
        etag = role_info.get("etag", "etag-1")

        actions = [CommonAction.from_string(p, provider="gcp") for p in permissions]
        stmt = CommonStatement(
            sid="RolePermissions",
            effect=PolicyEffect.ALLOW,
            actions=actions,
            resources=[CommonResource(arn_or_id="*")],
        )

        return CommonPolicy(
            id=role_key,
            name=role_info.get("title", policy_id),
            provider="gcp",
            version=etag,
            statements=[stmt],
            provider_metadata={"etag": etag, "stage": "GA"},
        )

    def analyze_permissions(self, role_id: str) -> Dict[str, Any]:
        policy = self.inspect_policy(role_id)
        if not policy:
            return {}
        perms = policy.extract_permission_strings()
        return {
            p: {
                "permission": p,
                "provider": "gcp",
                "state": "OBSERVED_OR_CONFIGURED",
                "risk": "high" if "admin" in p or "delete" in p else "low",
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
            provider="gcp",
        )

    def simulate_change(self, role_id: str, proposed_permissions: List[str]) -> SimulationResult:
        """Simulation is not natively supported by GCP IAM adapter."""
        raise UnsupportedCapabilityError(
            provider="gcp",
            operation="simulate_change",
            reason="Provider 'gcp' does not support native pre-commit simulation. Requires Security Health Analytics or policy preview escalation.",
            limitations=["No provider-native simulator in this adapter", "Pre-commit policy evaluation unsupported locally"],
        )

    def validate_change(self, target: Any) -> ProviderValidationResult:
        return validate_gcp_binding(target)

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
                details=[f"GCP role '{role_id}' not found"],
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
            details=["GCP binding verification complete."],
        )

    def apply_change(self, role_id: str, new_permissions: List[str], reason: str) -> PolicyVersion:
        # In GCP, updating role bindings alters IAM policy with etag concurrency
        version_obj = PolicyVersion(
            version_id="etag-updated",
            permissions=new_permissions,
            created_by="agent",
            reason=reason,
        )
        role_key = role_id if role_id.startswith("roles/") else f"roles/{role_id}"
        if role_key in self._roles_data:
            self._roles_data[role_key]["permissions"] = new_permissions
            self._roles_data[role_key]["etag"] = "etag-updated"
        return version_obj

    def rollback_change(self, role_id: str, target_version: str) -> PolicyVersion:
        """Atomic rollback is not natively supported on GCP."""
        raise UnsupportedCapabilityError(
            provider="gcp",
            operation="rollback_change",
            reason="Provider 'gcp' does not support atomic policy rollback. Re-binding previous role definition must be executed manually.",
            limitations=["Manual binding restoration required", "Etag mismatch detection requires manual reconciliation"],
        )


class SimulatedGCPProvider(GCPProviderAdapter):
    """Explicit alias for simulated GCP provider."""
    pass


class RealGCPProvider(BaseProvider):
    """Production GCP IAM connector stub with disabled-by-default safeguards."""

    def __init__(self, project_id: str = "default-project") -> None:
        self.project_id = project_id
        self._capabilities = GCP_CAPABILITIES
        self._live_mutation_enabled = os.getenv("LIVE_MUTATION_ENABLED", "false").lower() in ("true", "1")

    def get_capabilities(self) -> ProviderCapabilities:
        return self._capabilities

    def inspect_principal(self, principal_id: str) -> Optional[CommonPrincipal]:
        raise NotImplementedError("RealGCPProvider requires GCP Cloud IAM credentials.")

    def inspect_policy(self, policy_id: str) -> Optional[CommonPolicy]:
        raise NotImplementedError("RealGCPProvider requires GCP Cloud IAM credentials.")

    def analyze_permissions(self, role_id: str) -> Dict[str, Any]:
        raise NotImplementedError("RealGCPProvider requires GCP Cloud IAM credentials.")

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
            provider="gcp",
        )

    def simulate_change(self, role_id: str, proposed_permissions: List[str]) -> SimulationResult:
        raise UnsupportedCapabilityError(
            provider="gcp",
            operation="simulate_change",
            reason="GCP live policy simulation is unsupported in this environment.",
        )

    def validate_change(self, target: Any) -> ProviderValidationResult:
        return validate_gcp_binding(target)

    def verify_change(
        self, role_id: str, expected_permissions: Optional[List[str]] = None
    ) -> ComprehensiveVerificationResult:
        raise NotImplementedError("RealGCPProvider verification requires live credentials.")

    def apply_change(self, role_id: str, new_permissions: List[str], reason: str) -> PolicyVersion:
        if not self._live_mutation_enabled:
            raise PermissionError("Live GCP mutation is disabled by default.")
        raise NotImplementedError("Live GCP mutation is not enabled.")

    def rollback_change(self, role_id: str, target_version: str) -> PolicyVersion:
        raise UnsupportedCapabilityError(
            provider="gcp",
            operation="rollback_change",
            reason="GCP does not support atomic rollback.",
        )


__all__ = [
    "GCPProviderAdapter",
    "SimulatedGCPProvider",
    "RealGCPProvider",
]

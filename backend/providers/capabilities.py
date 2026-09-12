"""Provider capabilities abstraction for multi-cloud parity awareness."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CapabilityStatus(BaseModel):
    """Machine-readable assessment of provider support for a specific operation."""

    provider: str = Field(..., description="Provider identifier, e.g. 'aws', 'gcp', 'azure'")
    operation: str = Field(..., description="Target operation, e.g. 'simulate_change', 'rollback_change'")
    supported: bool = Field(..., description="Whether operation is supported by the provider adapter")
    reason: str = Field(default="", description="Forensic rationale for support status")
    limitations: List[str] = Field(default_factory=list, description="Known operational limitations")
    risk: str = Field(default="low", description="Risk tier: 'read_only', 'simulation', 'mutation', 'unsupported'")


class ProviderCapabilities(BaseModel):
    """Encapsulates cloud provider IAM feature capabilities and parity boundaries."""

    provider_name: str = Field(..., description="Provider identifier, e.g. 'aws', 'gcp', 'azure'")

    # Granular capability flags
    supports_principal_inspection: bool = Field(default=True)
    supports_policy_inspection: bool = Field(default=True)
    supports_role_inspection: bool = Field(default=True)
    supports_binding_inspection: bool = Field(default=True)
    supports_policy_simulation: bool = Field(
        default=True, description="Whether provider supports pre-commit authorization simulation"
    )
    supports_policy_validation: bool = Field(default=True)
    supports_policy_preview: bool = Field(
        default=True, description="Whether provider supports generating dry-run policy previews"
    )
    supports_resource_scoping: bool = Field(
        default=True, description="Whether permissions can be scoped to specific resource ARNs/scopes"
    )
    supports_conditions: bool = Field(
        default=True, description="Whether conditional statement blocks are evaluated"
    )
    supports_policy_versioning: bool = Field(
        default=True, description="Whether native immutable policy revisions are maintained"
    )
    supports_dry_run: bool = Field(default=True)
    supports_apply: bool = Field(default=True)
    supports_rollback: bool = Field(
        default=True, description="Whether instant atomic rollback to a previous version is available"
    )
    supports_local_analysis: bool = Field(default=True)
    supports_dependency_analysis: bool = Field(default=True)

    supported_policy_types: List[str] = Field(
        default_factory=lambda: ["identity_based", "resource_based"],
        description="Supported policy categories",
    )
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # Backward compatibility for Phase 1 & 2 tests
    @property
    def supports_simulation(self) -> bool:
        return self.supports_policy_simulation

    @supports_simulation.setter
    def supports_simulation(self, value: bool) -> None:
        self.supports_policy_simulation = value

    def check_capability(self, operation: str) -> CapabilityStatus:
        """Deterministically evaluates if an operation is supported, returning structured metadata."""
        op = operation.lower().strip()

        # Simulation checks
        if op in ("simulate_change", "simulate_policy", "simulate_policy_change", "simulation"):
            if self.supports_policy_simulation:
                return CapabilityStatus(
                    provider=self.provider_name,
                    operation=operation,
                    supported=True,
                    reason="Pre-commit counterfactual simulation supported via deterministic engine",
                    limitations=[],
                    risk="simulation",
                )
            return CapabilityStatus(
                provider=self.provider_name,
                operation=operation,
                supported=False,
                reason=f"Local {self.provider_name.upper()} simulation is not implemented",
                limitations=[
                    "No provider-native simulator in this adapter",
                    "Pre-commit workflow simulation unavailable without external cloud validator",
                ],
                risk="unsupported",
            )

        # Rollback checks
        if op in ("rollback_change", "rollback_policy", "rollback_policy_change", "rollback"):
            if self.supports_rollback:
                return CapabilityStatus(
                    provider=self.provider_name,
                    operation=operation,
                    supported=True,
                    reason="Deterministic atomic policy rollback supported via versioning history",
                    limitations=[],
                    risk="mutation",
                )
            return CapabilityStatus(
                provider=self.provider_name,
                operation=operation,
                supported=False,
                reason=f"{self.provider_name.upper()} does not support atomic policy rollback",
                limitations=[
                    "Manual state reconstruction or binding recreation required",
                    "Atomic reversion not natively guaranteed by vendor IAM",
                ],
                risk="unsupported",
            )

        # Apply checks
        if op in ("apply_change", "apply_policy", "apply_policy_change", "apply"):
            if self.supports_apply:
                return CapabilityStatus(
                    provider=self.provider_name,
                    operation=operation,
                    supported=True,
                    reason="Controlled policy application supported",
                    limitations=[] if self.supports_policy_versioning else ["Non-versioned policy update"],
                    risk="mutation",
                )
            return CapabilityStatus(
                provider=self.provider_name,
                operation=operation,
                supported=False,
                reason=f"Policy mutation disabled for provider '{self.provider_name}'",
                limitations=["Live cloud mutations disabled by default"],
                risk="unsupported",
            )

        # Inspection checks
        if op in ("inspect_principal", "get_principal"):
            return CapabilityStatus(
                provider=self.provider_name,
                operation=operation,
                supported=self.supports_principal_inspection,
                reason="Principal identity inspection supported",
                risk="read_only",
            )

        if op in ("inspect_policy", "get_policy", "inspect_role", "get_role"):
            return CapabilityStatus(
                provider=self.provider_name,
                operation=operation,
                supported=self.supports_policy_inspection or self.supports_role_inspection,
                reason="Policy/Role document inspection supported",
                risk="read_only",
            )

        if op in ("inspect_binding", "get_binding"):
            return CapabilityStatus(
                provider=self.provider_name,
                operation=operation,
                supported=self.supports_binding_inspection,
                reason="Role binding inspection supported" if self.supports_binding_inspection else "Provider uses statement-based policies rather than binding objects",
                risk="read_only",
            )

        # Validation checks
        if op in ("validate_change", "validate_policy", "validation"):
            return CapabilityStatus(
                provider=self.provider_name,
                operation=operation,
                supported=self.supports_policy_validation,
                reason=f"Provider-aware structural validation supported for {self.provider_name.upper()}",
                risk="read_only",
            )

        # Analysis checks
        if op in ("analyze_permissions", "analyze_policy", "analysis"):
            return CapabilityStatus(
                provider=self.provider_name,
                operation=operation,
                supported=self.supports_local_analysis,
                reason="Deterministic local permission analysis supported",
                risk="read_only",
            )

        # Diff checks
        if op in ("compute_policy_diff", "diff"):
            return CapabilityStatus(
                provider=self.provider_name,
                operation=operation,
                supported=True,
                reason="Provider-aware policy diff supported",
                risk="read_only",
            )

        # Verification checks
        if op in ("verify_change", "verify_required_access", "verification"):
            return CapabilityStatus(
                provider=self.provider_name,
                operation=operation,
                supported=True,
                reason="Multi-dimensional verification supported",
                risk="read_only",
            )

        # Fallback for generic operation
        return CapabilityStatus(
            provider=self.provider_name,
            operation=operation,
            supported=True,
            reason="Operation permitted under default capability matrix",
            risk="read_only",
        )


def negotiate_capability(capabilities: ProviderCapabilities, operation: str) -> CapabilityStatus:
    """Convenience helper to negotiate capabilities before execution."""
    return capabilities.check_capability(operation)


# Standard profile templates conforming to truthful multi-cloud reality
AWS_CAPABILITIES = ProviderCapabilities(
    provider_name="aws",
    supports_principal_inspection=True,
    supports_policy_inspection=True,
    supports_role_inspection=True,
    supports_binding_inspection=False,
    supports_policy_simulation=True,
    supports_policy_validation=True,
    supports_policy_preview=True,
    supports_resource_scoping=True,
    supports_conditions=True,
    supports_policy_versioning=True,
    supports_dry_run=True,
    supports_apply=True,
    supports_rollback=True,
    supports_local_analysis=True,
    supports_dependency_analysis=True,
    supported_policy_types=["identity_based", "resource_based", "service_control"],
)

GCP_CAPABILITIES = ProviderCapabilities(
    provider_name="gcp",
    supports_principal_inspection=True,
    supports_policy_inspection=True,
    supports_role_inspection=True,
    supports_binding_inspection=True,
    supports_policy_simulation=False,  # GCP IAM requires security health analytics or live policy simulator
    supports_policy_validation=True,   # Validates role bindings and IAM members
    supports_policy_preview=True,
    supports_resource_scoping=True,
    supports_conditions=True,
    supports_policy_versioning=False,  # Etag based concurrency rather than version history
    supports_dry_run=False,
    supports_apply=True,
    supports_rollback=False,           # Re-apply previous policy binding
    supports_local_analysis=True,
    supports_dependency_analysis=False,
    supported_policy_types=["role_binding", "conditional_binding"],
)

AZURE_CAPABILITIES = ProviderCapabilities(
    provider_name="azure",
    supports_principal_inspection=True,
    supports_policy_inspection=True,
    supports_role_inspection=True,
    supports_binding_inspection=True,  # RBAC role assignments
    supports_policy_simulation=False,  # Azure requires Azure Policy evaluation engine
    supports_policy_validation=True,   # Validates role definitions and assignments
    supports_policy_preview=False,
    supports_resource_scoping=True,
    supports_conditions=True,
    supports_policy_versioning=False,  # Role assignments without revision history
    supports_dry_run=False,
    supports_apply=True,
    supports_rollback=False,           # Role assignment deletion/recreation
    supports_local_analysis=True,
    supports_dependency_analysis=False,
    supported_policy_types=["rbac_role_assignment", "role_definition"],
)

RESTRICTED_MOCK_CAPABILITIES = ProviderCapabilities(
    provider_name="restricted_mock",
    supports_principal_inspection=True,
    supports_policy_inspection=False,
    supports_role_inspection=False,
    supports_binding_inspection=False,
    supports_policy_simulation=False,
    supports_policy_validation=False,
    supports_policy_preview=False,
    supports_resource_scoping=False,
    supports_conditions=False,
    supports_policy_versioning=False,
    supports_dry_run=False,
    supports_apply=False,
    supports_rollback=False,
    supports_local_analysis=False,
    supports_dependency_analysis=False,
    supported_policy_types=["basic"],
)

__all__ = [
    "CapabilityStatus",
    "ProviderCapabilities",
    "negotiate_capability",
    "AWS_CAPABILITIES",
    "GCP_CAPABILITIES",
    "AZURE_CAPABILITIES",
    "RESTRICTED_MOCK_CAPABILITIES",
]
